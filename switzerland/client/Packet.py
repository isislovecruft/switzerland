import hashlib
import sys
import hmac
import struct
import socket as s
import binascii
from array import array
import logging

from switzerland.common import Protocol

log = logging.getLogger('alice.packet')


zero = "\x00"
zerozero = array("c","\x00\x00")

# This short snippet to calculate header length from pcap_datalink was captured
# from pcap.pyx in the pycap project.

DLT_NULL =  0
DLT_EN10MB =    1
DLT_EN3MB = 2
DLT_AX25 =  3
DLT_PRONET =    4
DLT_CHAOS = 5
DLT_IEEE802 =   6
DLT_ARCNET =    7
DLT_SLIP =  8
DLT_PPP =   9
DLT_FDDI =  10
# XXX - Linux
DLT_LINUX_SLL = 113
# XXX - OpenBSD
DLT_PFLOG =     117
DLT_PFSYNC =    18
if sys.platform.find('openbsd') != -1:
    DLT_LOOP =      12
    DLT_RAW =       14
else:
    DLT_LOOP =      108
    DLT_RAW =       12


PCAP_DATALINK_TO_HEADER_LENGTH = {
    DLT_NULL:4, DLT_EN10MB:14, DLT_IEEE802:22, DLT_ARCNET:6,
    DLT_SLIP:16, DLT_PPP:4, DLT_FDDI:21, DLT_PFLOG:48, DLT_PFSYNC:4,
    DLT_LOOP:4, DLT_RAW:0, DLT_LINUX_SLL:16 
}


# XXX XXX handle truncated and othewise mangled packets with more subtlety
# (we currently will just raise exceptions and PacketListener will recover)
# This means that packes which trip the parser can be injected with impunity.

class Packet:
    """ captured user packet (IP datagram) """

    def __init__(self, timestamp, data, alice, hash = None):
        """ timestamp: when received, seconds since epoch
            data: (string) link layer data
            hash: (string) hash of packet contents """
        self.timestamp = timestamp
        self.alice = alice
        self.private_ip = s.inet_aton(alice.config.private_ip)
        self.original_data = data
        self.hash = hash
        self.reported = False
        self._flow_addr = None
        self.normalize_data()  # sets self.data
        self.decode_flow_info()
        self.key="XXX frogs"

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

        header_length = PCAP_DATALINK_TO_HEADER_LENGTH[self.alice.config.pcap_datalink]

        if (self.alice.config.pcap_datalink == 1): #if ethernet, check for IPv4 and vlans
            if (ord(self.original_data[12]) == 0x81 and ord(self.original_data[13]) == 0x00):
                # eth + vlan, 4 extra bytes of header
                assert ord(self.original_data[16]) == 0x00 and \
                    ord(self.original_data[17]) == 0x08,\
                    "pcap_datalink was 1 with vlan but not IPv4"
                header_length = header_length + 4
            else:
                # check for IPv4
                assert ord(self.original_data[13]) == 0x00 and \
                    ord(self.original_data[12]) == 0x08,\
                    "pcap_datalink was 1 but not IPv4 packet"
        # if not ethernet, just trust header length
        self.data = array("c",self.original_data[header_length:])

        # XXX remove all the magic numbers from this thing!!!
        # XXX check that this is an IP packet more robustly!!!
        # XXX make less poorly bad!!!

        # Zero the type of service (which shouldn't routinely change,
        # but does)
        self.data[1] = zero

        # zero the TTL:
        self.data[8] = zero
        # zero the header checksum (perhaps we should note if it's wrong,
        # too)
        self.data[10:12] = zerozero

        if self.data[9] == '\x06': # This is TCP.  Clear the checksum field
            self.tcp_start = self.ip_payload_start()
            # zero the TCP checksum
            self.data[self.tcp_start+16:self.tcp_start+18] = zerozero
            # do perverse things to the options:
            self.process_tcp_options()

        # check for and remove ethernet trailer
        total_length = struct.unpack(">H", self.data[2:4])[0]
        if total_length < 46 and len(self.data) == 46:
            del self.data[total_length:]

    def ip_payload_start(self):
        return ((ord(self.data[0]))&15) << 2

    def decode_flow_info(self):
        """ decode packet contents for flow tracking """
        self.size = len(self.data)
        self.flags = ord(self.data[6]) & 0xE0
        self.fragment_offset = (ord(self.data[6]) & 0x1f) * 256 \
          + (ord(self.data[7]))
        self.proto = self.data[9]
        self.source_ip = self.data[12:16].tostring()
        self.dest_ip = self.data[16:20].tostring()
        payload_start = self.ip_payload_start()
        self.ipid = self.data[4:6].tostring()
        self.alice.fm.ipids[self.ipid] = "Pending"
        if self.proto == '\x06' or self.proto == '\x11': # TCP or UDP
            self.source_port = self.data[payload_start:payload_start+2].tostring()
            self.dest_port = self.data[payload_start+2:payload_start+4].tostring()
        else: # portless protocol
            self.source_port = '\xff\xff'
            self.dest_port = '\xff\xff'


        self._flow_addr = self.source_ip + self.source_port + \
            self.dest_ip + self.dest_port + self.proto

    def process_tcp_options(self):
      """
      Some routers may routinely do things to TCP options.  Here we will
      have to work around those practices:
      * We sort selective acknowledgement (SACK) fields to be 
        reordering-invariant.
      """
      # >>2 means rotate right by 4, then multiply by 4-byte chunks
      tcp_header_length = ((ord(self.data[self.tcp_start+12]) & 0xF0)>>4) * 4
      if tcp_header_length > 20:
        # This packet contains TCP options
        pos = self.tcp_start+20  # start of TCP options
        while pos < self.tcp_start + tcp_header_length:
          kind = ord(self.data[pos])
          if kind == 0:  # EOL
            break
          if kind == 1:  # NOP
            len = 1
          elif kind == 5: # SACK
            len = ord(self.data[pos+1])
            if (len -2) % 8 != 0:
              log.warn("Packet with unreasonable TCP SACK Section length:")
              log.warn(binascii.hexlify(self.original_data))

            # some routers seem to reorder SACKs!!!  So we sort them 
            # before hashing :(
            # each SACK is a window of two 4 byte sequence numbers
            slots = range(pos+2,pos+len,8)
            sacks = [self.data[p:p+8] for p in slots]
            sacks.sort()
            for sack,p in zip(sacks, slots):
              self.data[p:p+8] = sack
          else:          # Any other TCP option
            len = ord(self.data[pos+1])
          pos += len
          if len == 0:
            pos += 1   # avoid an infinite loop vulnerability

    def is_fragment(self):
        """ is this a fragmented packet? """
        # if the MORE FRAGMENTS bit is set, or if the fragment offset 
        # is non-zero
        return ( (self.flags & 0x20) or (self.fragment_offset) )

    def flow_addr(self):
        """ get flow information from header"""
        return self._flow_addr

    def zero_source_port(self):
        self.data[self.tcp_start+0:self.tcp_start+2] = zerozero

    def zero_dest_port(self):
        self.data[self.tcp_start+2:self.tcp_start+4] = zerozero

    def get_hash(self):
        """ get hash of packet (SHA-1) """
        #print "hashing", self.data
        if self.hash:
            return self.hash

        if self.data[9] == '\x06':             # TCP

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

            # XXX some firewalls seem to change IP ID fields.  This is weird
            # and bad and confusing.  It probably exposes us to attacks based
            # on IP ID trickery.  But for the time being we seem to have to
            # do this if either end is firewalled.  We may avoid this in the
            # future by having two hash components, only one of which masks
            # things like this (or type of service) out            

            self.data[4:6] = zerozero

          if self.peer_firewalled:
            self.data[4:6] = zerozero
            # zero their port number
            if outbound:
              self.zero_dest_port()
            else:
              self.zero_source_port()

        elif self.data[9] == '\x11':
          # XXX do the same with udp!
          pass

        m = hmac.new(self.key,self.data,hashlib.sha1)
        self.hash = m.digest()[:Protocol.hash_length-2] + self.ipid
        self.alice.fm.ipids[self.ipid] = self.hash[:-2]

        return self.hash

#vim: et ts=4
