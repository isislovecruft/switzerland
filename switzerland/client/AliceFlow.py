import types
import socket as s
from binascii import hexlify
import logging

from switzerland.client import PacketQueue
from switzerland.common.Flow import Flow
from switzerland.client.Packet import Packet
from switzerland.common import Protocol

log = logging.getLogger("alice.flow")

class AliceFlow(Flow):
    """ AliceFlow includes a PacketQueue for holding batches. """

    def __init__(self, inbound, src_ip, src_port, dest_ip, dest_port, proto, now, opening_hash, in_circle):
        """
        inbound:      is the local host receiving data in this flow?
        src_ip:       sender's ip
        src_port:     sender's tcp/udp port
        dest_ip:      receiver's ip
        dest_port:    receiver's tcp/udp port
        proto:        ip protocol
        now:          timestamp of first packet in flow
        opening_hash: hash of first packet in flow (for firewall penetration)
        """
        Flow.__init__(self, inbound, src_ip, src_port, dest_ip, dest_port, proto, now, in_circle)
        self.queue = PacketQueue.PacketQueue()
        self.opening_hash = opening_hash
        self.marked_for_deletion = False

    def clean(self, now):
        """ clean out packets that have timed out """
        self.queue.clean(now)

    def summary(self):
        """
        Produce the representation to be sent to Switzerland in an
        active_flows message.
        """
         
        x = self
        return (x.id, x.opening_hash, (x.src_ip, x.src_port, x.dest_ip, x.dest_port, x.proto)) 

    def get_fo_context(self, context, alice):
        """ get packets bracketed by hashes from context = [("timestamp", "hash", "data")]
            XXX this is pretty stupid currently
        """
        min_match, max_match = None, None

        # need at least one packet of context 
        # (first elt of context is forged hash)
        if not context or len(context)<2:
            return None
        t_ts, t_hash, t_data = context[0]
        target_packet = Packet(t_ts, t_data, alice, has_ll=True)
        wanted_ip_id = target_packet.ip_id
        log.info("Target IP ID is " + hexlify(wanted_ip_id))
        wanted_seq = target_packet.tcp_seq
        # This ensures that we won't falsely match all non-TCP packets 
        if wanted_seq == None: 
            wanted_seq = -1
            log.info("No target TCP sequence number")
        else:
            log.info("Target TCP seq is " + `wanted_seq`)

        # these hashes surround our candidate source packets for forgeries
        # (leave out the forged hash itself which is context[0])    
        wanted_hashes = {}

        # XXX we could also use construct "wanted_ip_ids" here, but that
        # would require us to pass the ip_ids back from switizerland, or to
        # construct a Packet() for each data, which could get expensive
        # until we have controls on how large context can grow.
        for ts,hash,data in context[1:]:
            wanted_hashes[hash] = 1

        # scan batch queue and collect all non-context packets between
        # the earliest hash in context and the latest
        # XXX expensive
        matches = []
        num_matches = 0
        after_max = 0
        for i in xrange(len(self.queue)):
            batch = self.queue[i]
            for j in xrange(len(batch)):
                p = batch[j]
                # packet matches context
                if p.ip_id == wanted_ip_id or p.tcp_seq == wanted_seq or \
                              p.hash in wanted_hashes:
                    matches.append((p.timestamp, p.hash, p.original_data))
                    if min_match == None:
                        min_match = (i, j)
                    max_match = (i, j)
                    after_max = 0
                # else if we've seen the start of the run, scoop this
                # packet up as a potential match
                elif min_match and num_matches < Protocol.fo_context_max:
                    matches.append((p.timestamp, p.hash, p.original_data))
                    num_matches += 1
                    after_max += 1
                    # XXX to avoid iterating twice, we'll potentially
                    # keep elements after the max hash
                    # (this way doesn't rely on timestamps or assume that
                    # there's only one occurrence of each hash)

        if after_max >= 1:
            # slice off after_max elts from the right
            matches = matches[:-after_max] 
        return matches

    def get_fi_context(self, ts, hash):
        """ return fi-context for desired hash and timestamp """

        # find batch, if any, with desired newest_timestamp
        min_ts = ts - Protocol.fi_context_cutoff_time
        max_ts = ts + Protocol.fi_context_cutoff_time
        batch_id = None
        for i in xrange(len(self.queue)):
            batch = self.queue[i]
            batch_ts = batch.newest_timestamp
            if ts == batch_ts and batch.contains_hash(hash):
                batch_id = i; break
            elif batch_ts > max_ts:
                break # past the point of interest

        # if batch found, gather packet with hash and neighbors
        if batch_id != None:
            return self.get_context_from_batch(hash, batch_id, min_ts, max_ts)

        # if batch not found, return None
        # XXX might still have context within fi_context_cutoff_time
        return None

    def get_context_from_batch(self, hash, batch_id, min_ts, max_ts):
        # find packet in batch with desired hash
        batch = self.queue[batch_id]
        p = batch.find_hash(hash)

        # XXX will this fail if we have two batches with identical 
        # timestamps?...
        assert p != -1, 'expected to find packet'

        # get, return [ packet, before, after ]
        pkt = batch[p]
        packets = [ (pkt.timestamp, pkt.hash, pkt.original_data) ]
        pkt.reported = True
        self.__get_before_context(packets, p, batch_id, Protocol.fi_context_before, min_ts)
        self.__get_after_context(packets, p, batch_id, Protocol.fi_context_after, max_ts)                
        return packets

    def __get_before_context(self, packets, p, b, num, oldest_wanted):
        """ add to packets num packets before p in batch b """
        batch = self.queue[b]
        for n in xrange(num):
            p = p - 1    
            if p < 0:
                b = b - 1
                if b < 0:
                    return
                batch = self.queue[b]
                p = len(batch)-1
            pkt = batch[p]
            if pkt.timestamp < oldest_wanted:
                return
            if not pkt.reported:
                packets.append((pkt.timestamp, pkt.hash, pkt.original_data))
                pkt.reported = True

    def __get_after_context(self, packets, p, b, num, newest_wanted):
        """ add to packets num packets after p in batch b """
        batch = self.queue[b]
        for n in xrange(num):
            p = p + 1
            if p >= len(batch):
                b = b + 1
                if b >= len(self.queue):
                    return
                batch = self.queue[b]
                p = 0
            pkt = batch[p]
            if pkt.timestamp > newest_wanted:
                return
            if not pkt.reported:
                packets.append((pkt.timestamp, pkt.hash, pkt.original_data))
                pkt.reported = True

