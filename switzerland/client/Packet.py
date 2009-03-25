import sha
import sys
import hmac
import struct
import socket as s
import binascii
from array import array
import logging

from switzerland.common import Protocol

# Packet.py -- parse packets and calculate their hash fragments primarily used
# in the client but PacketDiff.py also leans on some of the work we do here.

track_ip_ids = True

# XXX Some control variables, to exclude certain kinds of underlying packet
# variations from the hash of the packet.  These were implemented before
# we understood the true scope of crazy behaviour by existing NATs.  There
# could be dozens of these variables, and if they were all enabled, we would
# probably never detect any modificatios at all.  The "right" way to do
# things in the future will probably be to start with most or all of these
# being false and to turn them on through a process of negotiation after
# modifications have been observed, and in consultation with NAT
# fingerprinting.  But that will be complicated. 

zero_ip_id = True
normalise_tcp_options = True
zero_type_of_service = True

# (Another strategy would be to have a "strong" and a "weak" portion of the
# hash; only the bare minimum of fields would be zeroed for the strong
# portion.  That would work well if there was a set of common and fairly
# inoccuous things that changed in flight.  Unfortunately many things that
# NATs change, such as ACK numbers and Do Not Fragment bits, are inherently
# problematic)

##################################

log = logging.getLogger('alice.packet')

# Zero'd bytes (octets) of length 1 and 2.
zero = "\x00"
zerozero = array("c", "\x00\x00")

# XXX: These variables should go; instead the PROTOCOLS dict in common/util.h
# should be used. But since we may want to move that dict to a file of its own,
# I'll not make the change now.
PROT_TCP = '\x06'
PROT_UDP = '\x11'
PROT_SCTP = '\x84'
PROT_DCCP = '\x21'
# RDP has its ports in a different place

# These are protocols that have 2 byte source and dest ports at the beginning
# of the payload
std_port_protocols = [PROT_TCP, PROT_UDP, PROT_SCTP, PROT_DCCP]

# XXX XXX some other protocols will 

# This short snippet to calculate header length from pcap_datalink was captured
# from pcap.pyx in the pycap project.

DLT_NULL = 0
DLT_EN10MB = 1
DLT_EN3MB = 2
DLT_AX25 = 3
DLT_PRONET = 4
DLT_CHAOS = 5
DLT_IEEE802 = 6
DLT_ARCNET = 7
DLT_SLIP = 8
DLT_PPP = 9
DLT_FDDI = 10
# XXX - Linux
DLT_LINUX_SLL = 113
# XXX - OpenBSD
DLT_PFLOG = 117
DLT_PFSYNC = 18
if sys.platform.find('openbsd') != -1:
    DLT_LOOP = 12
    DLT_RAW = 14
else:
    DLT_LOOP = 108
    DLT_RAW = 12

PCAP_DATALINK_TO_HEADER_LENGTH = {
    DLT_NULL: 4, DLT_EN10MB: 14, DLT_IEEE802: 22, DLT_ARCNET: 6,
    DLT_SLIP: 16, DLT_PPP: 4, DLT_FDDI: 21, DLT_PFLOG: 48, DLT_PFSYNC: 4,
    DLT_LOOP: 4, DLT_RAW: 0, DLT_LINUX_SLL: 16 
}

# XXX XXX handle truncated and othewise mangled packets with more subtlety
# (we currently will just raise exceptions and PacketListener will recover)
# This means that packes which trip the parser can be injected with impunity.
# Well, not quite impunity.  The user will be told about the weird packets,
# but won't know that they're forged.

class Packet:
    """Captured user packet (IP datagram)."""

    def __init__(self, timestamp, data, alice, hash=None, has_ll=True):
        """Create a new packet.
        
        timestamp: when received, seconds since epoch
        data: (string) link layer data
        hash: (string) hash of packet contents
        """

        self.timestamp = timestamp
        self.alice = alice
        self.private_ip = s.inet_aton(alice.config.private_ip)
        self.strip_link_layer = has_ll
        self.original_data = data
        self.hash = hash
        self.reported = False
        self._flow_addr = None
        self.normalize_data()  # sets self.data
        self.decode_flow_info()
        self.key = "XXX frogs"

    def __len__(self):
        return self.size

    def normalize_data(self):
        """ 
        Discard MAC header and zero out changing fields in an IP datagram
        (TOS, TTL, IP header checksum, TCP header checksum [for offloading]).
        also discard ethernet trailer if present
        """

        # Check that these are packets we know how to deal with.
        # If they trigger, PacketListener will catch them

        if self.strip_link_layer:
            header_length = PCAP_DATALINK_TO_HEADER_LENGTH[self.alice.config.pcap_datalink]

            if (self.alice.config.pcap_datalink == 1): #if ethernet, check for IPv4 and vlans
                if (ord(self.original_data[12]) == 0x81 and ord(self.original_data[13]) == 0x00):
                    # eth + vlan, 4 extra bytes of header
                    assert ord(self.original_data[16]) == 0x00 and \
                        ord(self.original_data[17]) == 0x08, \
                        "pcap_datalink was 1 with vlan but not IPv4"
                    header_length = header_length + 4
                else:
                    # check for IPv4
                    assert ord(self.original_data[13]) == 0x00 and \
                        ord(self.original_data[12]) == 0x08, \
                        "pcap_datalink was 1 but not IPv4 packet"
            # if not ethernet, just trust header length
            self.data = array("c", self.original_data[header_length:])
            self.ll_len = header_length
        else:
            self.data = array("c", self.original_data)
            self.ll_len = 0

        # XXX remove all the magic numbers from this thing!!!

        # Zero the type of service (which shouldn't routinely change, but does)
        if zero_type_of_service:
            self.data[1] = zero

        # Zero the TTL.
        self.data[8] = zero
        # Zero the header checksum (perhaps we should note if it's wrong, too).
        self.data[10:12] = zerozero

        self.ip_payload = self.ip_payload_start()
        if self.data[9] == PROT_TCP: # This is TCP.  Clear the checksum field
            # zero the TCP checksum
            self.data[self.ip_payload + 16:self.ip_payload + 18] = zerozero
            # do perverse things to the options:
            if normalise_tcp_options:
                self.process_tcp_options()

        # check for and remove ethernet trailer
        total_length = struct.unpack(">H", self.data[2:4].tostring())[0]
        if total_length < 46 and len(self.data) == 46:
            self.trailer_len = len(self.data) - total_length
            del self.data[total_length:]
        else:
            self.trailer_len = 0

    def ip_payload_start(self):
        return (ord(self.data[0]) & 15) << 2

    def decode_flow_info(self):
        """ decode packet contents for flow tracking """
        self.size = len(self.data)
        self.flags = ord(self.data[6]) & 0xE0
        self.fragment_offset = (ord(self.data[6]) & 0x1f) * 256 \
          + (ord(self.data[7]))
        self.proto = self.data[9]
        self.source_ip = self.data[12:16].tostring()
        self.dest_ip = self.data[16:20].tostring()
        self.ip_id = self.data[4:6].tostring()
        if track_ip_ids:
            self.alice.fm.ip_ids[self.ip_id] = "Pending"
        if self.proto in std_port_protocols: # TCP or UDP
            pl = self.ip_payload
            self.source_port = self.data[pl:pl + 2].tostring()
            self.dest_port = self.data[pl + 2:pl + 4].tostring()
        else: # portless protocol
            self.source_port = '\xff\xff'
            self.dest_port = '\xff\xff'

        if self.proto == '\x06':
            self.tcp_seq = struct.unpack(">I", self.data[4:8].tostring())[0]
        else:
            self.tcp_seq = None

        self._flow_addr = self.source_ip + self.source_port + \
            self.dest_ip + self.dest_port + self.proto

    def process_tcp_options(self):
        """
        Some routers may routinely do things to TCP options.  Here we will
        have to work around those practices:
        * We sort selective acknowledgement (SACK) fields to be 
          reordering-invariant.
        """
        # >> 4 means rotate right by 4, then multiply by 4-byte chunks
        tcp_header_length = ((ord(self.data[self.ip_payload + 12]) & 0xF0) >> 4) * 4
        if tcp_header_length > 20:
            # This packet contains TCP options
            pos = self.ip_payload + 20  # start of TCP options
            while pos < self.ip_payload + tcp_header_length:
                kind = ord(self.data[pos])
                if kind == 0:  # EOL
                    break
                if kind == 1:  # NOP
                    len = 1
                elif kind == 5: # SACK
                    len = ord(self.data[pos + 1])
                    if (len - 2) % 8 != 0:
                        log.warn("Packet with unreasonable TCP SACK Section length:")
                        log.warn(binascii.hexlify(self.original_data))

                    # Some routers seem to reorder SACKs!!!  So we sort them 
                    # before hashing :(
                    # Each SACK is a window of two 4-byte sequence numbers.
                    slots = range(pos + 2, pos + len, 8)
                    sacks = sorted(self.data[p:p + 8] for p in slots)
                    for sack, p in zip(sacks, slots):
                        self.data[p:p + 8] = sack
                else:          # Any other TCP option
                    len = ord(self.data[pos + 1])

                if len == 0:
                    # Avoid an infinite loop vulnerability
                    log.warn("Packet with reported TCP Option Length 0:")
                    log.warn(binascii.hexlify(self.original_data))
                    len = 1

                pos += len

    def is_fragment(self):
        """ is this a fragmented packet? """
        # if the MORE FRAGMENTS bit is set, or if the fragment offset 
        # is non-zero
        return (self.flags & 0x20) or self.fragment_offset

    def flow_addr(self):
        """ get flow information from header"""
        return self._flow_addr

    # XXX add RDP here but note it has different port locations in the header
    def zero_source_port(self):
        if self.data[9] in std_port_protocols:
            self.data[self.ip_payload + 0:self.ip_payload + 2] = zerozero

    def zero_dest_port(self):
        if self.data[9] in std_port_protocols: 
            self.data[self.ip_payload + 2:self.ip_payload + 4] = zerozero

    def get_hash(self):
        """ get hash of packet (SHA-1) """
        if self.hash:
            return self.hash

        # The following changes depend on knowing whether the peer is
        # firewalled, which we don't know when we first construct this Packet.
        # So we make them at hashing time instead...

        if self.source_ip == self.private_ip:
          outbound = True
        else:
          outbound = False
          assert self.dest_ip == self.private_ip, "neither of " +\
          `(s.inet_ntoa(self.source_ip), s.inet_ntoa(self.dest_ip))` +\
          "is " + self.private_ip

        if self.alice.link.firewalled:
            # zero our port number, rewrite our ip
            pub_ip = array("c", s.inet_aton(self.alice.link.public_ip))
            if outbound:
                self.zero_source_port()
                # overwrite source ip
                self.data[12:16] = pub_ip
            else:
                self.zero_dest_port()
                # overwrite dest ip
                self.data[16:20] = pub_ip 

            if zero_ip_id:
                self.data[4:6] = zerozero

        # self.peer_firewalled gets written in by the FlowManager
        if self.peer_firewalled:
            self.data[4:6] = zerozero
            # zero their port number
            if outbound:
                self.zero_dest_port()
            else:
                self.zero_source_port()

        m = hmac.new(self.key, self.data, sha)
        self.hash = m.digest()[:Protocol.hash_length - 2] + self.ip_id
        if track_ip_ids:
            self.alice.fm.ip_ids[self.ip_id] = self.hash[:-2]

        return self.hash

#vim: et ts=4
