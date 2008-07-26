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
from switzerland.common.PcapLogger import PcapLogger
from switzerland.server import Reconciliator
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
                    format="[%(name)s]: %(message)s")
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

    self.peer_lock = threading.RLock()
    self.peer_ips = {}

    self.flow_matchmaker = {}
    self.global_flow_lock = threading.RLock()

    self.one_forgery = False # for debugging
    self.special_forgery_debugging = False
    if self.special_forgery_debugging and not Reconciliator.hash_archival:
      raise ValueError, "cannot do special debugging without special archival"
        
    self.bughunt = {}
    if self.config.logging:
      self.log = PcapLogger(self.config.pcap_logdir)

    task = util.ThreadLauncher(self.flow_printer)
    task.setDaemon(True)
    task.start()


  def accept_connections(self):
    self.debug_note("Server listening for connections on port " +`self.config.port`+"...")
    while True:
      try:
        incoming, peer_addr = self.socket.accept()
      except KeyboardInterrupt:
        errlog.info("Server Exiting...")
        try:
          self.socket.shutdown(s.SHUT_RDWR)
        except:
          errlog.info("(exception on shutdown)")
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

      # it's important to have new_members calculations performed in
      # sensible order; SwitzerlandLink.initial_members and 
      self.peer_lock.acquire()
      try:
        link = self.new_link(incoming, peer_addr)
      finally:
        self.peer_lock.release()

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
    return link

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
          link.bailout("Too many simultaneous connections from the one IP!")
          return True
      self.debug_note("But they are all firewalled, so we'll let this in")
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
      self.debug_note("Joining circle, notifying %d others" % (len(self.peer_ips) -1) )
      for ip,links in self.peer_ips.items():
        if ip == new_ip:
          continue
        for port,l in links.items():
          if l.ready.isSet():
            self.send_other_message(l, "new-members", [[(new_ip_packed, firewalled)]])

      link.welcomed.set()      # the link threads can now farewell us :)
    finally:
      self.peer_lock.release()

  def link_closed(self, link):
    "Called from within each SwitzerlandLink's listener thread, upon closure."
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
        self.debug_note("Error in link_closed", link)
        errlog.info("%s", `self.peer_ips`)
        raise
    finally:
      self.peer_lock.release()

    # 2. Remove all of its active flows
    link.flow_lock.acquire()
    try:
      for f_tuple, rec in link.flow_table.values():
        self.remove_flow_from_matchmaker(rec)
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
      for port,l in links.items():
        self.send_other_message(l,"farewell", [leaving_ip])

  def send_other_message(self, link, msg, args, **keywords):
    """
    Use this function to send messages to other links.  We should ensure
    that this thread can't die along the way.  Return True if we succeeded,
    and False if the link died.
    """
    try:
      link.send_message(msg, args, **keywords)
      return True
    except:
      errlog.error("Error sending %s message to %s:\n%s\nArgs: %s" % 
                   (msg, `link.peer`, traceback.format_exc(), args))
      link.close()
      link.free_resources()
      return False
    

  def handle_active_flows(self, link, args):
    "The active_flows message from Alice updates our state of flows."
    new_flows, deleted_flows = args

    # Process deleted flows first, because we might want to delete a flow
    # and recreate it simultaneously if it has been closed and re-SYNed

    try:
      if not self.config.keep_reconciliators:
        self.debug_note("deleting flows: %s" % deleted_flows)
        for f_id in deleted_flows:
          self.delete_flow(link, f_id)
    except:
      link.protocol_error("Problem with flow list: %s\n" % util.screensafe(new_flows))
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

        mm = self.ponder_flow(link, f_id, f_tuple, opening_hash)
        if mm:
          self.debug_note("YES", seriousness=-1)
          self.add_flow(link, f_id, f_tuple, mm)
        else:
          self.debug_note("NO", seriousness=-1)
          if not self.config.sloppy:
            self.debug_note("Mysteriously Irrelevant Flow!!!%s" %
                            `(link.peer[0],print_flow_tuple(f_tuple))`)

    except:
      errlog.debug("OH NOES %s", sys.exc_info()[:2])
      link.protocol_error("Problem with flow list: %s\n" % util.screensafe(new_flows))
      raise


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

      ip1b = f_tuple[FlowTuple.src_ip]
      ip1 = s.inet_ntoa(ip1b)
      ip2b = f_tuple[FlowTuple.dest_ip]
      ip2 = s.inet_ntoa(ip2b)

      if ip1 == link_ip and ip2 in self.peer_ips:
        return (match_ip, ip2b, opening_hash)
      if ip2 == link_ip and ip1 in self.peer_ips:
        return (ip1b, match_ip, opening_hash)

    finally:
      self.peer_lock.release()
    link.flow_lock.acquire()
    try:
      link.flow_table[alice_id] = None
    finally:
      link.flow_lock.release()
    return False

  def delete_flow(self, link, alice_id):
    "Remove a flow from the link and global flow tables."
    link.flow_lock.acquire()
    try:
      entry = link.flow_table[alice_id]
      if entry == None:
        # We should never have had this flow anyway
        del link.flow_table[alice_id]
        return None
      f_tuple, rec = entry
      del link.flow_table[alice_id]
    finally:
      link.flow_lock.release()
    self.remove_flow_from_matchmaker(rec)

  def remove_flow_from_matchmaker(self, rec):
    self.global_flow_lock.acquire()
    # The other link will still have a reference to the Flows and
    # Reconciliator, so it won't matter if its gone from the flow_matchmaker
    try:
      try:
        # XXX research question: this table entry contains Flows and a
        # Reconciliator that references those flows.  Do we need to do more
        # to avoid garbage collection difficulties?
        del self.flow_matchmaker[rec.m_tuple]
      except KeyError:
        pass
    finally:
      self.global_flow_lock.release()


  def add_flow(self, link, id, f_tuple, m_tuple):
    """
    We have a newly reported flow from a client.  Ensure that the proper data
    structures are in place for it.  In this instance we assume that either
    end could be firewalled.
    """

    # This is a bit tricky.  First, we adopt the convention that Alice is
    # always the sender for a flow, and Bob the receiver (so for a TCP
    # session, each end is Alice in one direction and Bob in the other).

    # Next, observe that both Alice and Bob will send "active-flows"
    # messages adding the flow.  Those might arrive in either order.
    # Furthermore, Bob might send an "active-flows", then a whole lot of
    # "recv"s, long before Alice sends her "active-flow" -- so whichever end
    # sends first needs to trigger the instantiation of the Flows and the
    # Reconciliator.  
    
    # XXX There are some nasty special cases we don't currently handle here:
    # 1. The first packet in a flow is mangled in transit, so the
    # opening_hashes don't match.  The port numbers will sometimes tip us of
    # to this
    # 2. The first packet in a flow does not arrive first.  This shouldn't
    # be possible for TCP, but it may well happen with other protocols.

    f = f_tuple
    self.global_flow_lock.acquire()
    try:
      if m_tuple not in self.flow_matchmaker:
 
        self.debug_note("Creating flow: %s" % `print_flow_tuple(f)`)
        rec = Reconciliator.Reconciliator(f,m_tuple)
        rec.add_link(link, id)         # it'll figure out which side we are

        self.flow_matchmaker[m_tuple] = rec
        self.debug_note("Matchmaker is now %s" %
                        `self.flow_matchmaker`, seriousness=-2)
      else:
        rec = self.flow_matchmaker[m_tuple]
        if rec.add_link(link, id):
          # we have two sides to this flow now
          if self.config.logging: 
            self.log.new_flow(print_flow_tuple(f_tuple), rec.id)
    finally:
      self.global_flow_lock.release()
    
    # now register the flow in the link itself
    link.flow_lock.acquire()
    try:
      link.flow_table[id] = (f_tuple, rec)
    finally:
      link.flow_lock.release()


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
    tag = link.peer[0]
    if tag not in self.bughunt:
      self.bughunt[tag] = open(tag + ".log", "w")
    self.bughunt[tag].write(`sent` + `args` + '\n')
    self.bughunt[tag].flush()

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
      if sent:
        forgeries = rec.sent_by_alice(timestamp, hashes)
        drops = rec.check_for_drops()
        if drops:
          self.debug_note("%d dropped packets!" % len(drops))
      else:
        forgeries = rec.recd_by_bob(timestamp, hashes)
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
          forgeies = forgeries[:1]
          timestamp, hash = forgeries[0]
          ipids = Reconciliator.bob_ipids[hash]
          #assert len(ipids) == 1, `ipids` + "is not of length 1!"
          for ipid in ipids:
            self.debug_note("We have a forgery.  Debugging IPID %s" % ipid)
            self.send_other_message(rec.src_links[0][0],"debug-ipid", [ipid])
            return
        
      self.debug_note("Observed %d modified or forged packets" %
                      len(forgeries), seriousness=5)

      forgeries = self.select_some_forgeries(forgeries)

      for link, id in rec.dest_links:

        remember = (forgeries, rec)

        self.send_other_message(link, "forged-in", [id, forgeries], \
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

  def handle_fi_context(self, link, args, seq_no, reply_seq_no):
    """
    A "fi-context" message is in reply to our previous "forged-in".
    """
    meta, data = args              # meta is paperwork from our side
                                   # data is from bob
    in_reply_to, remembered = meta

    if in_reply_to != "forged-in":
      link.protocol_error("reply %d should not be a fi-context message\n" %\
      reply_seq_no)
      sys.exit(0)
    
    forgeries, rec = remembered

    msgs = []
    log_filenames = []
    for forgery in forgeries:
      timestamp, hash = forgery
      context = data[hash]
      msgs.append((hash, context)) # by convention the actual forgery
                                   # should be context[0]

      # XXX should we do this later, since Alice is waiting?
      if self.config.logging:
        if not context:
          log.error("Bob couldn't find the original fi packet!")
          log_filenames.append("")
        else:
          # it's a bit tricky to decide what filename to put the logs in,
          # and the inbound and outbound filenames need to match; so we
          # figure them both out here and remember the outbound one for later
          out_filename = self.log.log_forged_in(context, id=rec.id)
          log_filenames.append(out_filename)

    token_for_bob = seq_no
    store = (log_filenames,rec,forgeries,token_for_bob)
    for alice, id in rec.src_links:
      self.send_other_message(alice,"forged-out", [id, msgs], 
                              data_for_reply=store)

  def handle_fo_context(self, link, args, reply_seq_no):
    meta, data = args
    in_reply_to, remembered = meta
    if in_reply_to != "forged-out":
      link.protocol_error("reply %d should not be a fo-context message\n" %\
      reply_seq_no)
      sys.exit(0)

    filenames,rec,forgeries,token_for_bob = remembered
    msgs = []
    if filenames == []:
      assert not self.config.logging, "Pcap log list empty while logging"
      filenames = [None] * len(forgeries)

    assert len(filenames) == len(forgeries), "Pcap logs do not match forgeries"

    # Alice's handle_forged_out should preserve the order of the forgeries

    for forgery,filename in zip(forgeries, filenames):
      timestamp, hash = forgery
      context = data[hash]
      msgs.append((timestamp, context)) # by convention the actual forgery
                                        # should be context[0]
      if self.config.logging:
        if context:
          self.log.log_forged_out(context, filename)
        else:
          errlog.info("No meaningful forged out context")

    for link, id in rec.dest_links:
      self.send_other_message(link, "forged-details", [id, msgs], \
                              reply_seq_no=token_for_bob)
       

  hook_callback = None # overwite if desired
  def hook_handle(self, link, args, seq_no, reply_seq_no):
    "You can copy this method over some other handler method for debugging."
    self.debug_note("Hook handle w/ %s, %s, %s" % (args, seq_no, reply_seq_no))
    if self.hook_callback:
      # this is a function that can be inserted by test cases
      self.hook_callback(self, link, args, seq_no, reply_seq_no)

  def judgement_day(self):
    """
    Used for testing: reconcile all packets now, regardless of when the
    latest information from the clients arrived.
    """
    self.global_flow_lock.acquire()
    self.debug_note("Entering judgement day")
    try:
      for rec in self.flow_matchmaker.values():
        rec.final_judgement()
    finally:
      self.global_flow_lock.release()
      
  def print_global_flow_table(self):
    "(An obsolete name.)"
    return self.print_flow_matchmaker()

  def flow_printer(self, print_mms=True):
    "Run this in a thread.  Print the global flow table from time to time"
    while True:
      time.sleep(21)
      self.print_flow_matchmaker(print_mms)

  def print_flow_matchmaker(self, print_mms=True):
    """
    Pretty print the global flow tables.  Return a tuple for testing:
    (total flow pairs, total reconciled packets, total leftovers)
    """

    # XXXXXX clean up this code ; also make the output it produces more
    # self explanatory!

    errlog.info("CURRENT FLOW TABLE:")
    self.global_flow_lock.acquire()
    flows = {}
    for rec in self.flow_matchmaker.values():
      flows[rec.flow] = rec
    plist = []
    total_leftovers = 0
    total_okay = 0
    total_dropped = 0
    total_forged = 0
    try:
      n = 0
      for mm, rec in self.flow_matchmaker.items():
        if rec.flow in flows:
          f = rec.flow
          reclist = [(f, rec)]  # list will be of length 1 or 2
          mirror = (f[2], f[3], f[0], f[1], f[4])
          if mirror in flows: 
            reclist.append((mirror, flows[mirror]))
          else:
            errlog.info("No mirror for %s", `mm`)

          for flow,rec in reclist:
            rec.lock.acquire()
            try:
              leftovers = rec.leftovers()
              total_leftovers += leftovers[0] + leftovers[1]
              okay = rec.okay_packets
              forged = rec.forged_packets
              total_forged += forged
              dropped = rec.dropped_packets
              total_dropped += dropped
              total_okay += okay
              info = "%d %s ok:%d forge:%d drop:%d / %s" % (n, print_flow_tuple(rec.flow), okay, forged, dropped, `leftovers`)
              if print_mms:
                i1 = s.inet_ntoa(rec.m_tuple[0])
                i2 = s.inet_ntoa(rec.m_tuple[1])
                i3 = binascii.hexlify(rec.m_tuple[2])
                info += "\n  %s" % `(i1, i2, i3)`
                plist.append(info)
              del flows[flow]
            finally:
              rec.lock.release()
          n += 1
      for line in plist:
        errlog.info(line)
    finally:
      self.global_flow_lock.release()
    return (n, total_okay, total_leftovers, total_forged, total_dropped)


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
