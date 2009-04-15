#!/usr/bin/env python

import sys
from threading import RLock
import socket as s
import logging
from binascii import hexlify
import time
import traceback

from switzerland.common import Protocol
from switzerland.common import util
from switzerland.common.Flow import print_flow_tuple

id_num = 0
id_lock = RLock()
TIMESTAMP = -1

drop_timeout = 30 # packet was dropped if not seen in this time
clock_safety_margin = 2.0 

dangling_timeout = 12.0 # if this much time has elapsed since one side of a
                        # Reconciliator has shown up, the other side is probably
                        # never going to show up

mark_everything_forged = False # for testing fi/fo context messages easily     
crazy_debugging = False
hash_archival = False
hash_event_archival = hash_archival and False

log = logging.getLogger('switzerland.reconciliator')

# for debugging madness
if hash_archival:
  alice_ipids = {}
  alice_hashes = {}
  alice_flows_by_hash = {}
  bob_ipids = {}
  bob_hashes = {}
  forged_history = []
  bob_flows_by_hash = {}
  events_by_hash = {}

class Dangling(Exception):
  pass

def makebatch(timestamp, hashes, alice, rec):
  """
  A factory for the special dicts that represent our batches.
  hashes is a string of concatenated hashes
  TIMESTAMP is a constant that must not collide with the hashes
  """
  
  batch = {TIMESTAMP:timestamp}
  pos = 0
  for n in xrange(Protocol.hashes_in_batch(hashes)):
    hash = hashes[pos : pos + Protocol.hash_length]
    # debugging madness
    hash, ipid = hash[:-2], hash[-2:]
    if hash_archival:
      if alice:
        alice_ipids.setdefault(hash,[]).append(ipid)
        alice_hashes.setdefault(ipid,[]).append(hash)
        alice_flows_by_hash.setdefault(hash,[]).append(rec)
      else:
        bob_ipids.setdefault(hash,[]).append(ipid)
        bob_hashes.setdefault(ipid,[]).append(hash)
        bob_flows_by_hash.setdefault(hash,[]).append(rec)

    batch.setdefault(hash, 0)
    batch[hash] += 1
    pos += Protocol.hash_length
  return batch


class Reconciliator:
  """ Compare what Alice says she sent to what Bob says he received.
      Report forgeries and dropped packets. """

  def __init__(self, flow, m_tuple):
    self.lock = RLock()
    self.m_tuple = m_tuple
    self.newest_information_from_a = 0
    self.newest_information_from_b = 0
    # XXX there is some silly redudancy here, because we don't calculate
    # which side (sending / receiving) is calling this constructor, so we
    # don't know which view of the flow we have until add_link is called
    self.flow=flow
    self.src_flow = None
    self.dest_flow = None
    self.ready = False
    self.respond_to_forgeries = True  # used by Swtizerland.py
    self.birthday = time.time()

    # These two structures are lists of batches:
    # we might have stored them like this:
    # [(timestamp, {hash1:int count1, hash2: int count2}), (timestamp2,{..]
    # but it's easier to delete by reference if we put the timestamp
    # _inside_ the hash, like this:
    # 
    # a_to_b : [{TIMESTAMP:timestamp, hash1:count1, hash2:count2}, ..]
    self.a_to_b = []
    self.b_from_a = []
    # These are dicts for the whole queue, mapping each hash to the batches
    # that contain at least one packet with that hash, something like:
    # sent_packets {hash1:[a_to_b[1], a_to_b[7], a_to_b[33]}
    self.sent_packets = {}
    self.recd_packets = {}

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
    if crazy_debugging:
      import cPickle
      archives = cPickle.load("archives.pickle")


  def add_link(self, link, id, f_tuple):
    "Figure out whether this link is alice or bob, and remember it"
    if f_tuple == None:
      log.error("add_link should not be called with f_tuple=None!!!!")
      return False
    self.lock.acquire()
    try:
      ip = s.inet_aton(link.peer[0])

      if ip == self.m_tuple[0]:
        self.src_links.append((link, id))
        self.src_flow = f_tuple
        if len(self.src_links) != 1:
          link.debug_note("Duplicate src_links: %s" % `self.src_links`)
      elif ip == self.m_tuple[1]:
        self.dest_links.append((link, id))
        self.dest_flow = f_tuple
        if len(self.dest_links) != 1:
          link.debug_note("Duplicate dest_links: %s" % `self.dest_links`)
      else:
        link.protocol_error("Argh, confused about links and reconciliators!\n")

      if self.dest_links and self.src_links:
        
        skew1 = max([l.get_clock_dispersion() for l,id in self.src_links])
        skew2 = max([l.get_clock_dispersion() for l,id in self.dest_links])
        self.max_clock_skew = (skew1 + skew2) + clock_safety_margin
        self.ready = True
        log.debug("We now have both sides of flow %s", print_flow_tuple(self.flow))
        return True # have both sides
      else:
        log.debug("We currently only have one side of flow: %s", print_flow_tuple(self.flow))
        return False
    finally:
      self.lock.release()
      
  def leftovers(self):
    "Return a pair of the number of unreconciled packets in this flow"
    return (len(self.sent_packets), len(self.recd_packets))

  def prettyprint(self):
    """
    Looks something like this:

CURRENT FLOW TABLE:                            okay  drop mod/frg pend t/rx prot
111.222.233.244:12345 > 244.233.222.211:78901 343004 10000 100001 1000/2331 icmp
(192.168.1.100:54343)   (192.168.33.212:2333) opening_hash: 
                      <                       
    """
    pub_src,pub_dest = map(s.inet_ntoa, self.m_tuple[0:2])
    o_hash = self.m_tuple[2]
    # the other side is the only reliable indicator of each side's
    # public port number
    try:
      pub_src += ":" + `util.bin2int(self.dest_flow[1])`
      pub_dest += ":" + `util.bin2int(self.src_flow[3])`
    except:
      log.error("Weird error caused by flow %s (%s, %s)" % (`self.flow`, \
                `self.dest_flow`, `self.src_flow`))
      log.error(traceback.format_exc())

    line1 = pub_src.center(21) + " > " + pub_dest.center(21)

    # 19 = len("192.168.1.100:65535") -- this should be okay unless
    # the private addresses & ports are rather unusual
    priv_src = priv_dest = "not firewalled".center(19)
    if self.src_links[0][0].alice_firewalled:
      priv_src = self.src_links[0][0].peers_private_ip
      priv_src += ":" + `util.bin2int(self.src_flow[1])`
    if self.dest_links[0][0].alice_firewalled: # here, alice means bob :)
      priv_dest = self.dest_links[0][0].peers_private_ip
      priv_dest += ":" + `util.bin2int(self.dest_flow[3])`

    line2 = "(%19s)   (%19s)" % (priv_src, priv_dest)

    line1+= " %6g %5g %6g %4g/%4g " % (self.okay_packets, self.dropped_packets,\
      self.forged_packets, len(self.sent_packets), len(self.recd_packets))
    line1 += util.prot_name(util.bin2int(self.flow[4]))
    return line1 + "\n" + line2

  __str__ = prettyprint


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
      log.debug("Forged in judgement %s", `forged`)
    if dropped:
      log.debug("Dropped in judgement %s", `dropped`)
    return (forged, dropped)

  def alice_sent_flow_status(self, timestamp):
    """ 
    called when alice reports status for a flow (e.g. that it was idle)
    this way we can know that alice didn't send a packet that bob received 
    even if alice doesn't send more packets afterwards
    """
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
    finally:
      self.lock.release()
    return dropped

  def sent_by_alice(self, timestamp, hashes):
    "Called by Switzerland.py as new sent packets are reported by Alice."
    self.lock.acquire()
    try:
      self.check_dangling()
      assert not self.finalized, 'packets arriving in finalized reconciliator'
      assert timestamp >= self.newest_information_from_a, \
        'expecting timestamp to be monotonically increasing %f < %f' % \
        (timestamp, self.newest_information_from_a)
      self.newest_information_from_a = timestamp

      batch = makebatch(timestamp,hashes,True,self)

      if hash_archival:
        for hash in batch:
          if hash in forged_history:
            # XXX This started out as a debugging sanity check, but now
            # perhaps this opens us to a DOS attack?  How else can we convey
            # the seriousness of this condition?  We should send error
            # messages to alice and bob; alice should probably be disconnected
            # because she's possibly a culprit...
            log.error("TIMING ERROR, sent packets arriving unacceptably late")
            sys.exit(1)

      self.__discard_from_new_batch(batch, self.recd_packets, self.b_from_a)
      # Are there any packets left in the batch?
      if len(batch) > 1:          # 0 or more packets -- TIMESTAMP takes 1 slot
        self.a_to_b.append(batch)
        for hash in batch:
          if hash != TIMESTAMP:
            self.sent_packets.setdefault(hash,[]).append(batch)
      forged = self.__check_for_forgeries()
    finally:
      self.lock.release()
    return forged

  def recd_by_bob(self, timestamp, hashes):
    "Very similar to sent_by_alice, but confusing if it's factorised."
    self.lock.acquire()
    try:
      self.check_dangling()
      assert not self.finalized, 'not expecting finalized'
      assert timestamp >= self.newest_information_from_b, \
        'expecting timestamp to be monotonically increasing %f < %f' % \
        (timestamp, self.newest_information_from_b)
      self.newest_information_from_b  = timestamp

      batch = makebatch(timestamp,hashes,False,self)
      self.__discard_from_new_batch(batch, self.sent_packets, self.a_to_b)
      # Are there any packets left in the batch?
      if len(batch) > 1:                 # TIMESTAMP still takes a slot
        self.b_from_a.append(batch)
        for hash in batch:
          if hash != TIMESTAMP:
            self.recd_packets.setdefault(hash,[]).append(batch)
      forged = self.__check_for_forgeries()
      # XXX check for drops?
    finally:
      self.lock.release()
    return forged

  def check_dangling(self):
    """
    A reconciliator is said to be dangling if for some reason it Alice and Bob
    never get matched (ie self.ready is never True).  Typical causes might be
    modifications to the opening packet that change opening_hash; Alice and Bob
    seeing different packets as the first packet in the flow (most likely if
    the flow is older than their circle membership), or a flow between Alice
    and someone other than Bob behind Bob's firewall.  Raise an Exception if
    we're deemed to be dangling.
    """
    if self.ready:
      return
    if time.time() > self.birthday + dangling_timeout:
      raise Dangling


  def __discard_from_new_batch(self, new_batch, other_dict, other_batches):
    "We have a new batch, now remove everything in it that matches."
    for hash, num in new_batch.items():
      if hash == TIMESTAMP or mark_everything_forged:
        continue
      while hash in other_dict:
        # the hash matches on the other side; discard it
        new_batch[hash] -= 1
        self.okay_packets += 1
        if hash_event_archival:
          event = "Discarded on receipt"
          events_by_hash.setdefault(hash,[]).append(event)
        # cancel with the oldest instance on the other side
        other_batch = other_dict[hash][0]
        other_batch[hash] -= 1
        # the other side probably only had one of this hash in that batch:
        if other_batch[hash] == 0:
          if hash_event_archival:
            event = "No more in batch"
            events_by_hash.setdefault(hash,[]).append(event)
          # so remove it:
          del other_batch[hash]
          # and remove that batch from their list of batches w/ this hash:
          del other_dict[hash][0]
          # and if that's now empty, they no longer have this hash at all:
          if other_dict[hash] == []:
            del other_dict[hash]
            if hash_event_archival:
              event = "Discard emptied other dict"
              events_by_hash.setdefault(hash,[]).append(event)

        if new_batch[hash] == 0:
          del new_batch[hash]
          if hash_event_archival:
            event = "Emptied on this side"
            events_by_hash.setdefault(hash,[]).append(event)
          #no copies of the hash left on our side, so we can't cancel further
          break

  def __check_for_forgeries(self):
    """ 
    a packet is a forgery if bob got it and we know alice didn't send it.
    we know alice didn't send a packet if
     - it isn't in sent_packets, and
     - alice has sent newer packets (or given a newer report of no activity).
    note: assuming clocks are synchronized to within max_clock_skew seconds
    note: bob can't receive a packet before alice sends it. 
    """ 
    if not self.ready:
      return []
    antideadline = self.newest_information_from_a - self.max_clock_skew
    forgeries = self.scan_batches(
      self.b_from_a, self.recd_packets, self.sent_packets,
      lambda b: b[TIMESTAMP] < antideadline
    )
    self.forged_packets += len(forgeries)
    if hash_archival:
      self.trace_forgery_event(forgeries)
    return forgeries

  def diagnose(self, dict):
    str = "Dict of length %d " % len(dict)
    entries = [len(batch) for batch in dict.values()]
    zeroes = len([e for e in entries if e == 0])
    ones = len([e for e in entries if e == 1])
    others = len([e for e in entries if e > 1])
    str += "%d 0s, %d 1s, %d 1+s" % (zeroes, ones, others)
    return str

  def trace_forgery_event(self, forgeries):
    if forgeries:
      for f in forgeries:
        assert len(f[1]) == Protocol.hash_length -2 # XXX transient
        forged_history.append(f[1])

    # debugging madness
    f = forgeries[0]
    b_hash = f[1]
    print hexlify(b_hash), "is a forgery"
    if hash_archival:
      ipids = bob_ipids[b_hash]
      print "IPIDs that match this forgery are:", ipids
      for ipid in ipids:
        a_hashes = alice_hashes.setdefault(ipid,[])
        print "  ", hexlify(ipid), "matches", map(hexlify,a_hashes),"from alice"
        for hash in a_hashes:
          a_ipids = alice_ipids[hash]
          print "    ", hexlify(hash), "matches", map(hexlify,a_ipids)
          if ipid in a_ipids:
            print "      (which is crazy!)"
            print "      Alice flows", alice_flows_by_hash.setdefault(hash,[])
            print "      Bob   flows", bob_flows_by_hash.setdefault(hash,[])
            if hash_event_archival:
              print "      History is", events_by_hash.setdefault(hash,[])


  def scan_batches(self, batches, dict, other_dict, condition):
    """
    Proceed through the list of batches in chronological order.
    For those old enough to match "condition", remove them from our dict.
    We know they should not match the other side's dict.
    ("side" = sent | received)
    """
    results = []
    pos = 0
    for batch in batches:
      if not condition(batch):
        break
      pos += 1
      for hash, num in batch.items():
        if hash != TIMESTAMP:
          # invariant 1:
          assert hash in dict, "hash %s is not in dict %s!" % (hash,self.diagnose(dict))
          # __discard_from_new_batch should ensure this:
          assert (hash not in other_dict) or mark_everything_forged
          # invariant 2:
          list_of_occurences = dict[hash]
          ptr = list_of_occurences.pop(0)
          assert ptr == batch
          if list_of_occurences == []:
            del dict[hash]
          if hash_event_archival:
            event = "Deleted in scan_batch"
            events_by_hash.setdefault(hash,[]).append(event)
          for i in xrange(num):
            results.append((batch[TIMESTAMP], hash))
    del batches[0:pos]
    return results
   
 
  def check_for_drops(self):
    """ a packet is dropped if alice sent it and we know bob didn't get it.
        we know bob didn't get a packet if it's been more than drop_timeout
        seconds since alice reported sending it """ 
    assert not self.finalized, 'not expecting finalized'
    self.lock.acquire()
    try:
      if not self.ready:
        return []
      dropped = self.scan_batches(
      self.a_to_b, self.sent_packets, 
      self.recd_packets, 
      lambda b: self.newest_information_from_b - b[TIMESTAMP] > drop_timeout)
    finally:
      self.lock.release()

    self.dropped_packets += len(dropped)
    return dropped

# vim: et ts=2
