#!/usr/bin/env python

import threading
import logging
import time
from switzerland.common.Flow import print_flow_tuple
from switzerland.common.PcapLogger import PcapLogger
from switzerland.common import util
from switzerland.server import Reconciliator

errlog = logging.getLogger('matchmaker')
errlog.setLevel(logging.WARN)

table_header = """CURRENT FLOW TABLE:                            Okay  Drop Mod/frg Pend_t/rx Prot\n"""

class Matchmaker:
    """
    The Matchmaker is responsible for determining when a flow reported by
    Alice to Bob and a flow reported by Bob to Alice are in fact the same
    flow.  In the absence of NATs, port forwarding, transparent proxies and
    soforth this would be trivial.  But it isn't.
    """

    def __init__(self, parent):
        self.flow_matchmaker = {}
        self.global_flow_lock = threading.RLock()
        self.parent = parent
        self.config = self.parent.config
        if self.config.logging:
            self.log = PcapLogger(self.config.pcap_logdir)
        task = util.ThreadLauncher(self.flow_printer, parent.handle_control_c,
                                   respawn=True)
        task.start()


    def add_flow(self, link, id, f_tuple, m_tuple):
        """ 
        We have a newly reported flow from a client.  Ensure that the
        proper data structures are in place for it.  In this instance we
        assume that either end could be firewalled.  
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
     
            errlog.info("Creating flow: %s" % `print_flow_tuple(f)`)
            rec = Reconciliator.Reconciliator(f,m_tuple)
            rec.add_link(link, id, f)        # it'll figure out which side we are

            self.flow_matchmaker[m_tuple] = rec
            errlog.debug("Matchmaker is now %s" % `self.flow_matchmaker`)
          else:
            rec = self.flow_matchmaker[m_tuple]
            if rec.add_link(link, id, f):
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


    def delete_flow(self, link, alice_id):
        "Remove a flow from the link and global flow tables."
        link.flow_lock.acquire()
        try:
            try:
                entry = link.flow_table[alice_id]
                if entry == None:
                    # We should never have had this flow anyway
                    del link.flow_table[alice_id]
                    return None
                f_tuple, rec = entry
                del link.flow_table[alice_id]
            except KeyError:
                log.warn("Attempted delete_flow %d but it's already gone"%alice_id)
                return None
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
                # Reconciliator that references those flows.  Do we need to do
                # more to avoid garbage collection difficulties?
                del self.flow_matchmaker[rec.m_tuple]
            except KeyError:
                pass
        finally:
            self.global_flow_lock.release()


    def judgement_day(self):
      """
      Used for testing: reconcile all packets now, regardless of when the
      latest information from the clients arrived.
      """
      self.global_flow_lock.acquire()
      errlog.warn("Entering judgement day")
      try:
        for rec in self.flow_matchmaker.values():
          rec.final_judgement()
      finally:
        self.global_flow_lock.release()

    def print_global_flow_table(self):
      "(An obsolete name.)"
      return self.prettyprint_flows()

    def flow_printer(self, print_mms=True):
      "Run this in a thread.  Print the global flow table from time to time"
      while True:
        time.sleep(21)
        self.prettyprint_flows()

    def prettyprint_flows(self, print_mms=True):
      """
      Pretty print the global flow tables.  Return a tuple for testing:
      (total flow pairs, total reconciled packets, total leftovers)
      """
      # XXX this function is too large and ugly and too complicated.  Fix it.

      errlog.info("\nCURRENT FLOW TABLE:                            okay  drop mod/frg pend t/rx prot")
      self.global_flow_lock.acquire()
      try:
        flows = {}
        for rec in self.flow_matchmaker.values():
          if rec.ready:
            flows[rec.flow] = rec
        plist = []         # server side list of summaries
        notifications = {} # maps link -> list of flow summaries
        total_leftovers = 0
        total_okay = 0
        total_dropped = 0
        total_forged = 0
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
                total_leftovers += sum(rec.leftovers())
                total_forged += rec.forged_packets
                total_dropped += rec.dropped_packets
                total_okay += rec.okay_packets
                try:
                  assert rec.ready    # debugging weird errors
                except:
                  continue
                summary = rec.prettyprint()
                plist.append(summary)
                for link,id in rec.src_links + rec.dest_links:
                  notifications.setdefault(link, []).append(summary)
                del flows[flow]
              finally:
                rec.lock.release()
            n += 1
        for summary in plist:
          errlog.info(summary)
        if self.config.send_flow_status_updates:
          for link, summaries in notifications.items():
            # don't send an identical flow table to a client repeatedly
            msg = "\n".join(summaries)
            if link.last_status != msg:
              link.last_status = msg
              link.send_other_message("flow-status", [table_header + msg])
      finally:
        self.global_flow_lock.release()
      return (n, total_okay, total_leftovers, total_forged, total_dropped)

