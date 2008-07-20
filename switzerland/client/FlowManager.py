import types
import socket as s
import threading
from binascii import hexlify
import logging
import sys

from switzerland.client.AliceFlow import AliceFlow
from switzerland.common.Flow import Flow
from switzerland.client import Packet

# These archives, and the methods that work with them, are only intended to
# facilitate the creation of test cases.  They're a way to cheat and
# identify the correct answers for comparisons between PCAP files

a_lock = threading.RLock()
archives = {}
log = logging.getLogger('alice.flow_manager')
logging.disable(logging.DEBUG)


class Peer():
    "This class holds all the information we store on a per-peer basis"
    def __init__(self, firewalled, key="XXX"):
        self.firewalled = firewalled
        self.traceroute = None # XXX implement
        self.key = key

class FlowManager:
    "FlowManager tracks active Flows (and also the Peers who are in our circle"

    def __init__(self, config, parent=None):
        self.flows = { }
        self.flow_id_to_address = { }
        self.new_flows = [ ]
        self.deleted_flows = [ ]
        self.unique_id = 0
        self.config = config
        self.private_ip = s.inet_aton(config.private_ip)
        self.lock = threading.RLock()
        self.batch_to_process = threading.Condition(self.lock)
        self.peers = {}
        self.parent = parent

        self.ipids = {}        # for debugging

    def farewell(self, old_peer):
        "A peer has left. Remove any outstanding flows with it."
        self.lock.acquire()
        try:
            ip = s.inet_aton(old_peer)
            del self.peers[ip] 
            for f in self.flows.values():
                if f.src_ip == ip or f.dest_ip == ip:
                    f.marked_for_deletion = True
            log.info("Peer %s has disconnected" % old_peer)
        finally:
            self.lock.release()

    def listen_for(self, new_peers):
        "Start sniffing packets from these peers."
        self.lock.acquire()
        try:
            note = "Listening for traffic with peers: "
            for p,firewalled in new_peers:
                # XXX add a test for private IPs here
                # s.inet_ntoa(p) asserts that p is a valid peer address
                new = s.inet_ntoa(p)
                assert s.inet_ntoa(p) != self.parent.link.private_ip
                assert s.inet_ntoa(p) != self.parent.link.public_ip

                self.peers[p] = Peer(firewalled)
                note += new
                if firewalled: note += '*'
                note += ", "
            note = note[:-2] # chop off the last comma & space
            log.info(note)
        finally:
            self.lock.release()


    def is_peer_firewalled(self, peer):
        "Here to let a packet know if its peer is firewalled"
        self.lock.acquire()
        try:
          return self.peers[peer].firewalled
        finally:
          self.lock.release()

    def is_local_flow(self, packet):
        """
        determine if this flow is to or from the local machine (Alice)
        so we can filter out broadcast traffic.
        """
        if self.config.ignore_nonlocal_packets:
          if packet.dest_ip == self.private_ip and packet.source_ip == self.private_ip: 
            log.warning("sniffing packets from self!")
          if packet.source_ip == self.private_ip or packet.dest_ip == self.private_ip:
            return True
          else:
            return False
        else:
          raise NotImplementedError, "Promiscuity not implemented"

        return True

    def mark_if_firewalled(self, packet):
        """
        flag whether peer in this packet is firewalled
        """
        if packet.dest_ip == self.private_ip:
          peer_ip = packet.source_ip
        elif packet.source_ip == self.private_ip:
          peer_ip = packet.dest_ip
        else:
          raise NotImplementedError, "Promiscuity not implemented"

        try:
          packet.peer_firewalled = self.is_peer_firewalled(peer_ip)
        except KeyError:
          # we don't know if they're firewalled, since they're
          # not a true peer
          packet.peer_firewalled = True

    def is_in_circle(self, packet):
        """
        determine if a packet is to or from a host in Alice's circle.
        packets to hosts outside Alice's circle will not be logged (unless
        config.filter_packets is False), however statistics will be kept
        and sent to switzerland (anonymously)
        """
        if not self.config.filter_packets:
          return True

        self.lock.acquire()
        try:
            if (packet.dest_ip not in self.peers) and \
               (packet.source_ip not in self.peers):
                return False
        finally:
            self.lock.release()
          
        return True

    def archive_packet(self, packet):
      global a_lock
      global archives
      if not self.config.keep_archives:
        return
      a_lock.acquire()
      try:
          thread = self.parent.link.thread_no()
          archive = archives.setdefault(thread,{})
          hash = packet.get_hash()
          archive.setdefault(hash,[]).append(packet)

      finally:
          a_lock.release()

    def create_flow(self, packet, flow_addr):
        """ create a new flow with given initial packet and flow id string """
        opening_hash = packet.get_hash()
        flow = AliceFlow(packet.dest_ip == self.private_ip, # inbound flow?
            packet.source_ip, packet.source_port, 
            packet.dest_ip, packet.dest_port, packet.proto, 
            packet.timestamp, opening_hash, self.is_in_circle(packet))
        flow.id = self.unique_id # internal serial# for flow, != flow_addr
        self.unique_id += 1
        if flow.in_circle: # only report flows in circle to switzerland
            self.new_flows.append(flow)
            log.info("Now testing flow #%d %s" % (flow.id, flow.__str__()))
            log.debug("(flow opens with hash: %s\npacket data: %s" % \
                (hexlify(opening_hash), hexlify(packet.data)))
            log.debug("masked from: %s)" % hexlify(packet.original_data))
        self.flows[flow_addr] = flow
        # map IP datagram flow info to our internal flow id
        self.flow_id_to_address[flow.id] = flow_addr


    def handle_packet(self, packet):
        """
        called for each incoming packet. if packet destined for alice from
        host in circle, find existing flow or detect new flow, then queue
        for that flow.  return True if the packet completes a PacketBatch,
        False otherwise.
        """
        assert isinstance(packet, Packet.Packet), 'expecting Packet'
        if not self.is_local_flow(packet): # ignore packets not from/to alice
            return False
        self.mark_if_firewalled(packet)
        self.archive_packet(packet)

        flow_addr = packet.flow_addr()
        if not self.flows.has_key(flow_addr): # create flow if it doesn't already exist
            self.create_flow(packet, flow_addr)

        flow = self.flows[flow_addr]
        assert flow != None, 'expecting to find flow'

        # track flow data
        flow.activity = True
        flow.time_last_active = packet.timestamp
        flow.bytes_transferred += len(packet)
        flow.packets_transferred += 1

        if flow.in_circle:
            return flow.queue.append(packet)
        return False

    def clean(self, now):
        """ remove inactive flows or stale packets in active flows """
        self.lock.acquire()
        try:
          for f in self.flows.keys():
              flow = self.flows[f]
              inactive = now - flow.time_last_active
              if inactive > Flow.timeout or flow.marked_for_deletion:
                  log.debug("Flow %s timed out, deleting", `flow`)
                  if flow.in_circle: # switzerland only knows about this flow if it's in alice's circle
                      self.deleted_flows.append(flow)
                  del self.flow_id_to_address[flow.id]
                  del self.flows[f]
              else:
                  flow.clean(now)
        finally:
          self.lock.release()

def save_archives():
  import cPickle
  pair = archives.values()
  pair.sort()
  first,second = pair
  cPickle.dump(archives,file)

def crawl_archives():
  """
  This basically tells us what the right answers for drop and forgery counts
  should be between paired PCAPs while using PcapPlayback.
  """
  assert len(archives) == 2, "oh no "+ `archives.keys()`
  pair = archives.values()
  pair.sort()
  first,second = pair
  for hash,list1 in first.items():
    str = `hash[:3]`
    l1 = len(list1)
    if hash not in second:
      log.debug("l1 only %s %d", str, l1)
      del(first[hash])
      continue
    list2 = second[hash]
    del second[hash]
    l2 = len(list2)
    if (l1 ==1) and (l2 == 1):
      log.debug("Matched hash %s offset %f", str, list1[0].timestamp - list2[0].timestamp)
    else:
      if l1 == l2:
        log.debug("Balanced multi-match %s %d", str, l1)
      else:
        log.debug("Imbalanced multi-match %s %d %d", str, l1, l2)
  for hash, list2 in second.items():
    str = `hash[:3]`
    log.debug("Other side: %s %d", str, len(list2))

