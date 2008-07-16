#!/usr/bin/env python

import util
from SwitzerlandFlow import SwitzerlandFlow
from threading import RLock
import socket as s

id_num = 0
id_lock = RLock()

class Reconciliator:
  """ Compare what Alice says she sent to what Bob says he received.
      Report forgeries and dropped packets. """

  drop_timeout = 120 # packet was dropped if not seen in this time
  max_clock_skew = 3.0 # max clock error + transmission time in seconds

  def __init__(self, a_to_b, b_from_a):
    assert isinstance(a_to_b, SwitzerlandFlow), 'expecting flow object'
    assert isinstance(b_from_a, SwitzerlandFlow), 'expecting flow object'
    self.lock = RLock()
    self.newest_information_from_a = 0
    self.newest_information_from_b = 0
    self.a_to_b = a_to_b
    self.b_from_a = b_from_a
    self.sent_packets = { }
    self.recd_packets = { }
    self.okay_packets = 0
    self.forged_packets = 0
    self.dropped_packets = 0
    self.finalized = False
    self.src_links = []
    self.dest_links = []
    global id_num, id_lock
    id_lock.acquire()
    self.id = id_num
    id_num += 1
    id_lock.release()

  def add_link(self, link, id):
    "Figure out whether this link is alice or bob, and remember it"
    ip = s.inet_aton(link.peer[0])

    if ip == self.a_to_b.src_ip:
      self.src_links.append((link, id))
      if len(self.src_links) != 1:
        link.debug_note("Duplicate src_links: %s" % `self.src_links`)
    elif ip == self.a_to_b.dest_ip:
      self.dest_links.append((link, id))
      if len(self.dest_links) != 1:
        link.debug_note("Duplicate dest_links: %s" % `self.dest_links`)
    else:
      link.protocol_error("Argh, confused about links and reconciliators!\n")

    if self.dest_links and self.src_links:
      return True # have both sides
    else:
      return False
    
  def leftovers(self):
    "Return a pair of the number of unreconciled packets in this flow"
    return (len(self.sent_packets), len(self.recd_packets))

  def final_judgement(self):
    """ flag newest information from alice and bob at infinity
        to be used in testcases to flag all remaining packets """
    self.lock.acquire()
    try:
      forged= self.alice_sent_flow_status(1e308)
      dropped = self.bob_sent_flow_status(1e308)
      self.finalized = True
    finally:
      self.lock.release()
    if forged:
      print "Forged in judgement,", forged
    if dropped:
      print "Dropped in judgement,", dropped
    return (forged, dropped)

  def alice_sent_flow_status(self, timestamp):
    """ called when alice reports status for a flow (e.g. that it was idle)
        this way we can know that alice didn't send a packet that bob received even
        if alice doesn't send more packets afterwards """
    self.lock.acquire()
    assert not self.finalized, 'not expecting finalized'
    try:
      try:
        assert timestamp >= self.newest_information_from_a, 'expecting timestamp to be monotonically increasing, %f < %f' % (timestamp, self.newest_information_from_a)
      except:
        util.debugger()
        raise
      self.newest_information_from_a = timestamp
      forged = self.__check_for_forgeries()
      self.forged_packets += len(forged)
    finally:
      self.lock.release()
    return forged

  def bob_sent_flow_status(self, timestamp):
    """ called when bob reports status for a flow (e.g. that it was idle) """
    self.lock.acquire()
    assert not self.finalized, 'not expecting finalized'
    try:
      try:
        assert timestamp >= self.newest_information_from_b, 'expecting timestamp to be monotonically increasing %f < %f' % (timestamp, self.newest_information_from_b)
      except:
        util.debugger()
        raise
      self.newest_information_from_b = timestamp
      dropped = self.check_for_drops()
      self.dropped_packets += len(dropped)
    finally:
      self.lock.release()
    return dropped

  def sent_by_alice(self):
    """ called when alice reports a new sent batch.
        returns hashes of forgeries, empty list if all are ok """
    self.lock.acquire()
    try:
      assert not self.finalized, 'not expecting finalized'
      timestamp = self.a_to_b.batches.last.data.timestamp
      try:
        assert timestamp >= self.newest_information_from_a, 'expecting timestamp to be monotonically increasing %f < %f' % (timestamp, self.newest_information_from_a)
      except:
        util.debugger()
        raise
      self.newest_information_from_a = timestamp

      self.__track_packets(self.sent_packets, self.recd_packets, self.a_to_b.batches, self.b_from_a.batches)

      forged = self.__check_for_forgeries()
      self.forged_packets += len(forged)
      #if forged:
      #  print "Sent by alice, forgeries", forged
      #else:
      #  print "Sent by alice, no forgeries"
    finally:
      self.lock.release()
    return forged
  
  def recd_by_bob(self):
    """ called when bob reports a new received batch.
        returns hashes of forgeries, empty list if all are ok """
    self.lock.acquire()
    assert not self.finalized, 'not expecting finalized'
    try:
      timestamp = self.b_from_a.batches.last.data.timestamp
      assert timestamp >= self.newest_information_from_b, 'expecting timestamp to be monotonically increasing'
      self.newest_information_from_b = timestamp

      self.__track_packets(self.recd_packets, self.sent_packets, self.b_from_a.batches, self.a_to_b.batches)
      #print "RECD_BY_BOB:"
      #print self
      #print self.recd_packets
      forged = self.__check_for_forgeries()
      self.forged_packets += len(forged)
    finally:
      self.lock.release()
    return forged

  def __track_packets(self, dict, other_dict, queue, other_queue):
    """ reference count packet hashes in a dictionary, dict
        discard hashes which already occur in another dictionary, other_dict """
    batch = queue.last
    assert batch != None, 'expecting a new batch'
    for node in batch.data.hash_list:
      hash = node.data

      # if hash was both received and sent, it was neither
      # dropped nor forged, so get rid of it.
      if other_dict.has_key(hash):
        self.__delete_hash(queue, batch, node)
        o_batch, o_node = other_dict[hash].pop(0)
        self.__delete_hash(other_queue, o_batch, o_node)
        if len(other_dict[hash]) == 0:
          del other_dict[hash]

        # the packet was reported by both ends so count it ok
        self.okay_packets += 1

      # otherwise keep track of packet
      else:
        dict.setdefault(hash,[]).append((batch,node))

  def __delete_hash(self, queue, batch, node):
    """ delete a hash from a batch
        if the batch is empty, delete it from its queue """
    hashes = batch.data.hash_list
    hashes.delete(node)
    if len(hashes) == 0:
      queue.delete(batch)

  def __check_for_forgeries(self):
    """ a packet is a forgery if bob got it and we know alice didn't send it.
        we know alice didn't send a packet if
        - it isn't in sent_packets, and
        - alice has sent newer packets (or given a newer report of no activity).
        note: assuming clocks are synchronized to within max_clock_skew seconds
        note: bob can't receive a packet before alice sends it. """ 
    return self.__scan_queue(\
      self.b_from_a.batches, self.recd_packets, \
      self.a_to_b.batches, self.sent_packets, \
      lambda t: t < self.newest_information_from_a - Reconciliator.max_clock_skew)
  
  def check_for_drops(self):
    """ a packet is dropped if alice sent it and we know bob didn't get it.
        we know bob didn't get a packet if it's been more than drop_timeout
        seconds since alice reported sending it """ 
    dropped = [ ]
    assert not self.finalized, 'not expecting finalized'
    self.lock.acquire()
    try:
      dropped = self.__scan_queue(
      self.a_to_b.batches, self.sent_packets, \
      self.b_from_a.batches, self.recd_packets, \
      lambda t: self.newest_information_from_b - t > Reconciliator.drop_timeout)
    finally:
      self.lock.release()
    return dropped

  def __scan_queue(self, queue, dict, other_queue, other_dict, cond):
    """ delete entries at head of batch queue matching cond,
        recording and returning any hashes not in dict. """
    match = [ ]
    while len(queue) != 0 and cond(queue.first.data.timestamp):
      for node in queue.first.data.hash_list:
        hash = node.data
        assert hash in dict

        # hash was sent but not received, or received but not sent
        if not hash in other_dict:
          match.append( (dict[hash][0][0].data.timestamp, hash) )
        else: # false alarm, hash matched
          try:
            raise SyntaxError, "never take this path"
          except:
            util.debugger()
          other_dict[hash].pop(0)
          if len(other_dict[hash]) == 0:
            del other_dict[hash]

          # delete from other queue since definitely no longer needed
          o_batch,o_node = dict[hash][0]
          self.__delete_hash(other_queue, o_batch, o_node)

          self.okay_packets += 1

        # clean up hash from the __track_packets dictionary
        dict[hash].pop(0)
        if len(dict[hash]) == 0:
          del dict[hash]

      queue.delete(queue.first)

    return match

# vim: et ts=2
