#!/usr/bin/env python2.5

import socket as s     # make all the constants less crazy
import sys
import threading
import time
import binascii
import logging
import traceback
import random
import time

from switzerland.common import Protocol
from switzerland.common import util
from switzerland.common.Flow import print_flow_tuple,FlowTuple
from switzerland.server import Reconciliator
from switzerland.server.Matchmaker import Matchmaker
from switzerland.server.SwitzerlandLink import SwitzerlandLink
from switzerland.server.SwitzerlandConfig import SwitzerlandConfig

# Do not investigate more than this number of modified packets at once:
max_forgery_set = 3

# Match ends of a flow if their hashes match but their IPIDs do not.
# This seems necessary to reconcile some flows through some NATs,
# but it means that we're down to the sequence number (and perhaps some
# TCP options) as the sole factors determining the opening hash, and that
# creates a non-zero risk of mistakenly matchmaking genuinely different flows
ipids_in_matchmaker = False

# The Switzerland-side threading model is currently as follows:

# * SwitzerlandMasterServer.accept_connections() runs in the main thread
#   of execution.

# * SwitzerlandMasterServer.new_link() it spawns off a SwitzerlandLink
#   thread for each client that is connected.

#   (the above will need to change in the future)

# * Most of the code in this class is only executed through the handle_*
#   methods, which are only ever called from within the link threads.

# * This means that most of the work done here (and in Reconciliator.py)
#   occurs in the same threads that are listening for data inside 
#   SwitzerlandLink.  Perhaps that will need to change at some point.

logging.basicConfig(level=logging.DEBUG,
                    format="%(message)s")
log = errlog = logging.getLogger('switzerland')

# remember that this does not have sufficient entropy for any cryptographic
# purposes
random.seed(time.time())

class SwitzerlandMasterServer:

  def __init__(self, config):
    self.config = config
    self.socket = s.socket(s.AF_INET, s.SOCK_STREAM)
    # This ensures we don't need to wait for a timeout every time this
    # process exits and then starts and tries to bind to this port again
    self.socket.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1L)
    self.socket.bind(("",self.config.port))
    self.socket.listen(5)
    self.threads = []
    task = util.ThreadLauncher(self.pinger, self.handle_control_c)
    task.start()

    self.peer_lock = threading.RLock()
    self.peer_ips = {}

    self.mm = Matchmaker(self)

    self.one_forgery = False # for debugging
    self.special_forgery_debugging = False
    if self.special_forgery_debugging and not Reconciliator.hash_archival:
      raise ValueError, "cannot do special debugging without special archival"
        

  def accept_connections(self):
    self.debug_note("Server listening for connections on port " +`self.config.port`+"...")
    while True:
      try:
        incoming, peer_addr = self.socket.accept()
      except KeyboardInterrupt:
        self.handle_control_c()
      # it's important to have new_members calculations performed in
      # sensible order; SwitzerlandLink.initial_members and 
      self.peer_lock.acquire()
      try:
        self.new_link(incoming, peer_addr)
      finally:
        self.peer_lock.release()

  def handle_control_c(self):
    "Urgent shutdown logic"
    errlog.info("Server Exiting...")
    try:
      self.socket.shutdown(s.SHUT_RDWR)
    except:
      errlog.info("(exception on shutdown)")
    try:
      try:
        self.peer_lock.acquire()
        for ip in self.peer_ips.values():
          for link in ip.values():
            try:
              link.close()
            except:
              errlog.error("problem closing %s", `link`)
      except:
        errlog.error("problem iterating over links")
        raise
    finally:
      self.peer_lock.release()
    self.socket.close()
    sys.exit(0)


  def debug_note(self, string, seriousness=0, link=None):
    if seriousness < self.config.seriousness_threshold:
      return
    if link:
      link.debug_note(string)
    else:
      errlog.debug("SwitzMas: " +string)

  def new_link(self, incoming, peer_addr):
    """
    Instantiate a SwitzerlandLink for a new connection and do the relevant
    housekeeping.
    """
    link = SwitzerlandLink(incoming, peer_addr, parent=self,
                           seriousness=self.config.seriousness_threshold)
    link.setDaemon(True)
    self.peer_lock.acquire()
    try:
      peer_ip,peer_port = peer_addr
        
      errlog.info("got a connection from %s %s", peer_ip, peer_port)
      if not self.is_duplicate_alice(link, peer_ip):
        self.peer_ips[peer_ip] = {}     # will become a dict of port numbers
      
      self.peer_ips[peer_ip][peer_port] = link
      self.debug_note("peers: %s" % `self.peer_ips`)
      self.threads.append(link)
    finally:
      self.peer_lock.release()
    
    self.debug_note("Initialising server thread")
    link.start()

  def is_duplicate_alice(self, link, peer_ip):
    """
    Return True if this client is a dupe; dupes may be admissable -- this
    function handles that too but it doesn't affect the return type (yuck)
    """
    # self.peer_lock has already been acquired in new_link()
    if peer_ip in self.peer_ips:
      # Oh dear, a second Alice from this IP!
      others = self.peer_ips[peer_ip]
      self.debug_note("Hmmm, we already have  "+ `len(others)`+ \
                      " connections from" + `peer_ip`)
      for p in others:
        try:
          if not p.alice_firewalled:
            link.bailout("We already have a non-firewalled client from your IP, %s!" % peer_ip)
            return True
        except AttributeError:
          # p.firewalled hasn't been determined yet
          link.bailout("We already have a connection from your IP.  Multiple connections from a single IP are currently disallowed!")
          return True
      #self.debug_note("But they are all firewalled, so we'll let this in")
      # no?
      return True
    else:
      return False

  def joining_circle(self, link):
    "this peer is joining us; tell everyone else"
    new_ip = link.peer[0]
    new_ip_packed = s.inet_aton(new_ip)
    firewalled = link.alice_firewalled
    self.peer_lock.acquire()
    try:
      assert new_ip in self.peer_ips
      self.debug_note("Joining circle, notifying %d others" % 
                                             (len(self.peer_ips) -1) )
      for ip,links in self.peer_ips.items():
        if ip == new_ip:
          continue
        for port,l in links.items():
          if l.ready.isSet():
            l.send_other_message("new-members", [[(new_ip_packed, firewalled)]])

      link.welcomed.set()      # the link threads can now farewell us :)
    finally:
      self.peer_lock.release()

  def link_closed(self, link):
    "Called from within each SwitzerlandLink's listener thread, upon closure."

    # XXX This might be insufficient unless we also find and remove all of the
    # references to this link that have been travelling around Matchmaker.py
    # and Reconciliator.py

    ip, port = link.peer
    self.peer_lock.acquire()
    self.debug_note("Closing link with client "+`ip` +" "+ `port`, link)
    # 1. Remove this link from our peer structures
    try:
      try:
        del self.peer_ips[ip][port]
        if len(self.peer_ips[ip]) == 0:
          self.send_farewells(ip)
          del self.peer_ips[ip]
      except KeyError:
        errlog.error("Error while closing link:\n%s", traceback.format_exc())
    finally:
      self.peer_lock.release()

    # 2. Remove all of its active flows
    link.flow_lock.acquire()
    try:
      for entry in link.flow_table.values():
        if entry != None:
          f_tuple, rec = entry
          self.mm.remove_flow_from_matchmaker(rec)
    finally:
      link.flow_lock.release()
      # XXX we don't want new flows being added after this, but failing
      # to release the lock would seem to be a very poor way of 
      # guaranteeing that

    # 3. Remove the thread
    if not self.config.keep_threads:
      self.threads.remove(link)


  def send_farewells(self, leaving_ip):
    """
    Tell peers that a link has gone away.
    Assumes peer_lock acquired already
    """
    for ip,links in self.peer_ips.items():
      if ip == leaving_ip:
        continue
      for port,link in links.items():
        link.send_other_message("farewell", [leaving_ip])

  def handle_active_flows(self, link, args):
    "The active_flows message from Alice updates our state of flows."
    new_flows, deleted_flows = args

    # Process deleted flows first, because we might want to delete a flow
    # and recreate it simultaneously if it has been closed and re-SYNed

    try:
      if not self.config.keep_reconciliators:
        self.debug_note("deleting flows: %s" % deleted_flows)
        for f_id in deleted_flows:
          self.mm.delete_flow(link, f_id)
    except:
      link.protocol_error("Problem with flow list: %s\n" % 
                                              util.screensafe(new_flows))
      raise

    # Now the new flows:
    try:
      for flow in new_flows:
        f_id = flow[0]
        if ipids_in_matchmaker:
          opening_hash = flow[1]
        else:
          opening_hash = flow[1][:-2]
        f_tuple = flow[2]

        match = self.ponder_flow(link, f_id, f_tuple, opening_hash)
        if match:
          self.debug_note("YES", seriousness=-1)
          self.mm.add_flow(link, f_id, f_tuple, match)
        else:
          self.debug_note("NO", seriousness=-1)
          if not self.config.sloppy:
            self.debug_note("Mysteriously Irrelevant Flow!!!%s" %
                            `(link.peer[0],print_flow_tuple(f_tuple))`)

    except:
      errlog.debug("OH NOES %s", sys.exc_info()[:2])
      link.protocol_error("Problem with flow list: %s\n" % 
                                            util.screensafe(new_flows))
      raise

  def judgement_day(self):
    self.mm.judgement_day()


  def print_global_flow_table(self):
    "(An obsolete name.)"
    return self.mm.prettyprint_flows()


  def faking_ip(self, link, to_ip):
    "Our link is faking for testing purposes..."
    self.peer_lock.acquire()
    try:
      from_ip, port = link.peer
      try:
        s.inet_aton(to_ip)
      except s.error:
        link.protocol_error("Invalid fake IP %s\n" % to_ip)
        
      link.debug_note("peer %s:%d is faking ip %s:%d"
                      %(from_ip,port,to_ip,port))
      del self.peer_ips[from_ip][port]
      if self.peer_ips[from_ip] == {}:
        del self.peer_ips[from_ip]
      if to_ip not in self.peer_ips:
        self.peer_ips[to_ip] = {}
      self.peer_ips[to_ip][port] = link
      self.debug_note("peers: %s" % `self.peer_ips`)
    finally:
      self.peer_lock.release()


  def ponder_flow(self, link, alice_id, f_tuple, opening_hash):
    """
    Sanity check before we allow a flow into our data structures.
    If yes, return a representation of the flow for our matchmaker.
    If no, return False.
    """

    # XXX decide whether to add promiscuity here
    self.peer_lock.acquire()
    try:
      self.debug_note("IS THIS RELEVANT to %s? %s %s" % (link.peer[0], 
      `print_flow_tuple(f_tuple)`, `self.peer_ips.keys()`), seriousness=-1)

      # link_ip is the ip we expect to find for this client inside its flows
      # match_ip is the ip we want to use for matchmaking

      match_ip = s.inet_aton(link.peer[0])
      if link.alice_firewalled:
        self.debug_note("..firewalled..", seriousness=-1)
        link_ip = link.peers_private_ip
      else:
        self.debug_note("..not firewalled..%s" % \
          `link.alice_firewalled`, seriousness=-1)
        link_ip  = link.peer[0]
      assert s.inet_aton(link_ip)

      self.debug_note("link and match: %s %s" % 
                      (link_ip,`match_ip`), seriousness=-1)

      ip1bin = f_tuple[FlowTuple.src_ip]
      ip1 = s.inet_ntoa(ip1bin)
      ip2bin = f_tuple[FlowTuple.dest_ip]
      ip2 = s.inet_ntoa(ip2bin)

      if ip1 == link_ip and ip2 in self.peer_ips:
        return (match_ip, ip2bin, opening_hash)
      if ip2 == link_ip and ip1 in self.peer_ips:
        return (ip1bin, match_ip, opening_hash)

    finally:
      self.peer_lock.release()
    link.flow_lock.acquire()
    try:
      link.flow_table[alice_id] = None
    finally:
      link.flow_lock.release()
    return False

  def peers_of(self, ip):
    """
    Return the data we need for new-members messages.  That is,
    (peer, firewalled) for all other peers who are in-circle for this ip.
    peer is a packed binary ip.
    """
    self.peer_lock.acquire()
    try:
      results = []
      for peer_ip, ports in self.peer_ips.items():
        if peer_ip == ip:
          continue

        # we want to add a record of whether each peer is firewalled or not
        # this turns out to be messy

        # some links won't be ready yet
        firewalled_answers = [link.alice_firewalled \
                              for link in ports.values() \
                              if "alice_firewalled" in link.__dict__]

        if len(firewalled_answers) == 0:
          continue
        first_answer = firewalled_answers[0]
        for answer in firewalled_answers[1:]:
          assert answer == first_answer, "Inconsistent firewalling for " + \
                           `peer_ip` + ", " + `firewalled_answers`

        results.append((s.inet_aton(peer_ip), first_answer))
          
      return results
    finally:
      self.peer_lock.release()

  def handle_sent_or_recd(self, link, args, sent):
    """
    Sent and recd messages are conceptually very similar, so this function
    handles both cases.  sent = True|False accordingly.
    """
    flow_id, timestamp, hashes = args
    link.flow_lock.acquire()
    try:
      entry = link.flow_table[flow_id]
    finally:
      link.flow_lock.release()

    if entry:
      rec = entry[1]
    else:
      # This flow is being ignored because it isn't between our peers
      return False
    rec.lock.acquire()
    try:
      try:
        if sent:
          forgeries = rec.sent_by_alice(timestamp, hashes)
          drops = rec.check_for_drops()
          if drops:
            self.debug_note("%d dropped packets!" % len(drops))
        else:
          forgeries = rec.recd_by_bob(timestamp, hashes)
      except Reconciliator.Dangling:
        opening_hash = rec.m_tuple[2]
        link.send_message("dangling-flow", [flow_id, opening_hash])
        log.warn("Flow %s is dangling" % `print_flow_tuple(rec.flow)`)
        link.flow_lock.acquire()
        try:
          link.flow_table[flow_id] = None
        finally:
          link.flow_lock.release()
        return
    finally:
      rec.lock.release()
    if forgeries:
      self.spotted_forgeries(forgeries, rec)
    if sent: s = "+"
    else: s = "-"
    if self.config.seriousness_threshold <=0:
      sys.stdout.write(s)
      sys.stdout.flush()

  def spotted_forgeries(self, forgeries, rec):
    # First, we need to find the link object from the other side
    rec.lock.acquire()
    try:
      # XXX XXX right now, only respond to the first forgeries event per flow
      # (to avoid runaway processing when every packet is being modified)
      # later perhaps the Correct Response is to use random sampling of
      # forgeries in the flow
      if not rec.respond_to_forgeries:
        return
      else:
        # This could become a counter that is set to a random number instead
        # of being permanently disabled
        rec.respond_to_forgeries = False

      sl = len(rec.src_links)
      if sl != 1:
        self.debug_note("forgeries with other than one src %d" % sl, 2)
      dl = len(rec.dest_links)
      if dl != 1:
        self.debug_note("forgeries with other than one dest %d" % dl, 2)

      # for debugging: only deal with the first forgery
      if self.special_forgery_debugging:
        if self.one_forgery:
          return
        else:
          self.one_forgery = True
          forgeries = forgeries[:1]
          timestamp, hash = forgeries[0]
          ipids = Reconciliator.bob_ipids[hash]
          #assert len(ipids) == 1, `ipids` + "is not of length 1!"
          for ipid in ipids:
            self.debug_note("We have a forgery.  Debugging IPID %s" % ipid)
            rec.src_links[0][0].send_other_message("debug-ipid", [ipid])
            return
        
      self.debug_note("Observed %d modified or forged packets" %
                      len(forgeries), seriousness=5)

      forgeries = self.select_some_forgeries(forgeries)

      for link, id in rec.dest_links:
        remember = (forgeries, rec)
        link.send_other_message("forged-in", [id, forgeries], \
                                data_for_reply=remember)

      # Now we wait for a response from Bob before talking to Alice
    finally:
      rec.lock.release()

  def select_some_forgeries(self, forgeries):
      """ 
      If we get a large number of forgeries, we can cause all sorts of
      overloading and misery.  So we only repond to max_forgery_set of them
      at once.
      
      The subset is selected pseudorandomly, so that inane activity (such as
      seen from NATs) won't completely obscure something nastier, like
      forged RSTs, just by happening before it.  
      """
      # XXX confirm that we don't need more genuine randomness here.  An
      # attack based on, especially since most Switzerland servers will be
      # continuously running this code for other Alice/Bob pairs that are
      # being affected by funy NATs

      if len(forgeries) > max_forgery_set:
        self.debug_note("(selecting %d of those)" % max_forgery_set)
        subset = []
        for i in xrange(max_forgery_set):
          pos = random.randrange(len(forgeries))
          subset.append(forgeries[pos])
          del forgeries[pos]
        return subset
      else:
        return forgeries

  def pinger(self):
    """ 
    Run this in a thread to ensure that we periodically talk to all of the
    clients.  If any of them are lost to us, that should be enough to raise an
    exception that leads to cleanup.  
    """
    while True:
      time.sleep(random.randrange(3,6))
      for thread in self.threads:
        if thread.time_since_contact() > 60:
          thread.send_other_message("ping", missing_ack_callback=thread.bye)

def flow_mirror((src_ip,src_port,dest_ip,dest_port,prot)):
  "Switch source and dest in a flow."
  return (dest_ip,dest_port,src_ip,src_port,prot)

      
def main():
  try:
    import psyco
    psyco.full()
  except:
    errlog.warn("psyco not available -- the server will be more efficient if psyco is installed")
  x = SwitzerlandMasterServer(SwitzerlandConfig(getopt=True))
  x.accept_connections()

if __name__ == "__main__":
  main()
# vim: et ts=2
