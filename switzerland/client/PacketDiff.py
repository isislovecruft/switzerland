#!/usr/bin/env python

import sys
import struct
import logging
import difflib

from switzerland.client import Packet
from binascii import hexlify
from util import hexhex

# PacketDiff.py -- figure out which fields in a packet have been modified
# in transit. 

log = logging.getLogger('packetdiff')

commentary = False


class PacketDiffer:
    def __init__(self, a_pkt, b_pkt, alice, apakobj=None, bpakobj=None):
        if apakobj:
            self.apakobj = apakobj
        else:
            apakobj = self.apakobj = Packet.Packet(0, a_pkt, alice)
        if bpakobj:
            self.bpakobj = bpakobj
        else:
            bpakobj = self.bpakobj = Packet.Packet(0, b_pkt, alice)
        
        # We need to strip link layers and ethernet trailers, but we can
        # piggyback off Packet.py already having figured this out
        if apakobj.trailer_len:
            self.a_pkt = a_pkt[apakobj.ll_len:-apakobj.trailer_len]
        else:
            # unfortunately list[x:-0] doesn't work
            self.a_pkt = a_pkt[apakobj.ll_len:]
        if bpakobj.trailer_len:
            self.b_pkt = b_pkt[bpakobj.ll_len:-bpakobj.trailer_len]
        else:
            self.b_pkt = b_pkt[bpakobj.ll_len:]

        self.conclusions = ""
        self.handle_total_lengths()

    def handle_total_lengths(self):
        result = ""
        # XXX handle the ethernet trailer here
        len_a,len_b = len(self.apakobj.data), len(self.bpakobj.data)
        if len_a > len_b:
            result += "Sent packet is %d bytes longer than the received packet;" 
            result %= len_a - len_b
            result += "the extra data from position %d is:\n" % len_b
            result += hexlify(self.a_pkt[len_b:]) + "\n"
            result += "(or in ASCII...)\n"
            result += self.a_pkt[len_b:]
        elif len_b < len_a:
            result += "Received packet is %d bytes longer than the sent packet;"
            result %= len_a - len_b
            result += "the extra data from position %d is:\n" % len_a
            result += hexlify(self.b_pkt[len_a:]) + "\n"

        self.conclusions += result

    def diff_tuple(self, atuple, btuple, guide):
        """
        Iterate through a tuple of packet fields, spotting any fields that
        differ across packets a and b.  Use the guide tuple to interpret any
        differences that are observed.  See eg ip_hdr_fields for guidance.
        """
        assert len(atuple) == len(btuple)
        for a,b,pos in zip(atuple, btuple, range(len(atuple))):
            field = guide[pos]
            if isinstance(field, IgnoreVariation):
                continue
            elif type(field) == str and a != b:
                self.modified_field(field, a, b)
            elif isinstance(field, SpecialCase):
                # The special cases include bitfields and firewall depedent
                # things
                field.handle(self,a,b)

    def modified_field(self, field, a, b, nohex=False):
        """
        This gets called whenever other code here concludes that something
        has been modifed.  It is responsible for adding human readable output
        to the conclusions, but it is also the place for hooks to other code
        in other parts of Switzerland.
        """
        if nohex:
            xform = lambda x:`x`
        else:
            xform = hexhex
        # A straightforward field: just report the variation
        results = "The %s field was modified in this packet " % field
        results += "(%s -> %s)\n" % (xform(a),xform(b))
        self.conclusions += results

    ip_hdr_baselen = 20
    def diff(self):
        # IP header (constant portion)
        ip_hdr_a = self.get_ip_hdr(self.a_pkt[:self.ip_hdr_baselen])
        ip_hdr_b = self.get_ip_hdr(self.b_pkt[:self.ip_hdr_baselen])
        if commentary:
            if ip_hdr_a[2] != len(self.apakobj.data):
                print "Length mismatch for alice", ip_hdr_a[2], \
                       len(self.apakobj.data)
            if ip_hdr_b[2] != len(self.bpakobj.data):
                print "Length mismatch for bob", ip_hdr_b[2], \
                       len(self.bpakobj.data)
        self.diff_tuple(ip_hdr_a, ip_hdr_b, ip_hdr_fields)
        # IP header (options)
        ip_opt_a = self.a_pkt[self.ip_hdr_baselen:self.a_ip_hdrlen]
        ip_opt_b = self.b_pkt[self.ip_hdr_baselen:self.b_ip_hdrlen]
        if ip_opt_a != ip_opt_b:
            self.grok_tcp_option_difference()
            #self.modified_field("IP header options", ip_opt_a, ip_opt_b)

        # TCP
        if ip_hdr_a[6] == ip_hdr_b[6] == Packet.PROT_TCP:
            self.diff_tcp()
        else:
            self.diff_other_transport_layer()
        return self.conclusions

    def grok_tcp_option_difference(self):
        # we know just by the fact we've been called that the TCP options
        # are different
        #for opt in apakobj.tcp_options
        pass

    def diff_tcp(self):
        # Core of the TCP header
        sa = self.a_ip_hdrlen
        tcp_hdr_a = self.get_tcp_hdr(self.a_pkt[sa:sa+20])
        sb = self.b_ip_hdrlen
        tcp_hdr_b = self.get_tcp_hdr(self.b_pkt[sb:sb+20])
        self.diff_tuple(tcp_hdr_a, tcp_hdr_b, tcp_hdr_fields)
        # TCP options
        if self.a_tcp_hdrlen > 20 or self.b_tcp_hdrlen > 20:
            a_tcp_opts = self.a_pkt[sa+20:sa+self.a_tcp_hdrlen]
            b_tcp_opts = self.b_pkt[sb+20:sb+self.b_tcp_hdrlen]
            if a_tcp_opts != b_tcp_opts:
                from switzerland.lib.shrunk_scapy.layers.inet import TCP
                a = TCP(self.a_pkt[sa:]) # scapy.TCP
                b = TCP(self.b_pkt[sb:])
                self.modified_field("TCP options", `a.options`, `b.options`, \
                                    nohex=True)
                #self.diff_tcp_opts(a_tcp_opts, b_tcp_opts)
        # payload data
        a_payload = self.a_pkt[sa+self.a_tcp_hdrlen:]
        b_payload = self.b_pkt[sb+self.b_tcp_hdrlen:]
        if a_payload != b_payload:
            self.modified_field("TCP payload", a_payload, b_payload, nohex=True)
            representation = "----- Attempting line-based diff:  -----\n" 
            from pprint import pformat
            diff = difflib.Differ().compare(b_payload.splitlines(1), 
                                            a_payload.splitlines(1))
            representation += pformat(list(diff))
            representation += "\n----- end diff -----\n"
            self.conclusions += representation 


    def diff_tcp_opts(self, a_opts, b_opts):
        # XXX improve
        if a_opts != b_opts:
            self.modified_field("TCP options", a_opts, b_opts)

    def diff_other_transport_layer(self):
        a_rest = self.a_pkt[:self.a_ip_hdrlen]
        b_rest = self.b_pkt[:self.b_ip_hdrlen]
        if a_rest != b_rest:
            self.modified_field("Transport layer data", a_rest, b_rest)


    # tcp_flags is a list of tuples of TCP flag names and their bitmasks
    flags = ["FIN", "SYN", "RST", "PSH", "ACK", "ECE", "CWR"]
    tcp_flags = [("TCP " + flag, 1 << pos) for flag,pos in zip(flags, range(8))]
    def handle_tcp_flags(self, a, b):
        "Determine and report which if any TCP flags have been changed."
        if a != b:
            a_bits = ord(a)
            b_bits = ord(b)
            axorb = a_bits ^ b_bits
            for flag_name, mask in self.tcp_flags:
              if axorb & mask:
                self.flag_modified(flag_name, a_bits & mask, b_bits & mask)
               
    def flag_modified(self, name, a_flag, b_flag):
        "Report a modification to the flag named `name'."
        if a_flag and not b_flag:
            change = "switched off"
        elif b_flag and not a_flag:
            change = "switched on"
        else:
            # If a flag is modified, it should be modified...
            log.error("ERROR, confused about modifications to %s flag" % name)
            return
        self.conclusions += "%s flag %s\n" % (name, change)

    def null_handler(self, a, b):
        log.warn("null handler called!")

    def handle_tcp_offset_etc(self, a, b):
        a = ord(a)
        b = ord(b)
        self.a_tcp_hdrlen = a >> 2  # rotate by 4 bits then multiply by 4
        self.b_tcp_hdrlen = b >> 2
        if self.a_tcp_hdrlen != self.b_tcp_hdrlen:
            self.modified_field("TCP offset/header length", self.a_tcp_hdrlen, \
                                self.b_tcp_hdrlen)
        a_res = a & 0x0f
        b_res = a & 0x0f
        if a_res != b_res:
            self.modified_field("TCP reserved bits", a_res, b_res)

    if sys.version_info > (2,5):
        get_ip_hdr = struct.Struct("!ccHHHccHII").unpack
    else:
        def get_ip_hdr(packet):
            return struct.unpack("!ccHHHccHII", packet)

    if sys.version_info > (2,5):
        get_tcp_hdr = struct.Struct("!HHIIccHHH").unpack
    else:
        def get_tcp_hdr(packet):
            return struct.unpack("!HHIIccHHH", packet)

    def handle_ip_hdr_len(self, a, b):
        a_ver, a_ihl = ord(a) & 0xf0, ord(a) & 0x0f
        b_ver, b_ihl = ord(b) & 0xf0, ord(b) & 0x0f
        a_ver, b_ver = a_ver >> 4, b_ver >> 4
        self.a_ip_hdrlen = a_ihl * 4
        self.b_ip_hdrlen = b_ihl * 4
        if a_ver != b_ver:
            self.modified_field("IP version", a_ver, b_ver)
        if a_ihl != b_ihl:
            self.modified_field("IP header length", a_ihl, b_ihl)

pd = PacketDiffer                

class IgnoreVariation:
    def __init__(self, explanation):
        self.explanation = explanation

class SpecialCase:
    def __init__(self, explanation, handle=pd.null_handler):
        self.explanation = explanation
        self.handle = handle
           

ip_hdr_fields = (
    SpecialCase("IP header length & version", pd.handle_ip_hdr_len),
    "IP type of service",
    "IP reported total packet length",
    "IP identification number",
    "IP fragment offset",
    IgnoreVariation("IP TTL"),
    "transport layer protocol reported in IP header",
    IgnoreVariation("IP checksum"),
    IgnoreVariation("Source IP"),
    IgnoreVariation("Destination IP")
)

tcp_hdr_fields = (
    IgnoreVariation("TCP source port"),
    IgnoreVariation("TCP destionation port"),
    "TCP sequence number",
    "TCP acknowledged sequence number",
    SpecialCase("TCP Data offset/reserved", pd.handle_tcp_offset_etc),
    SpecialCase("TCP flags", pd.handle_tcp_flags),
    "TCP Window",
    IgnoreVariation("TCP Checksum"),
    "TCP urgent pointer"
)


if __name__ == "__main__":
    logging.basicConfig()
    file1 = open(sys.argv[1])
    file2 = open(sys.argv[2])
    from switzerland.common.Dummies import DummyAlice
    p = PacketDiffer(file1.read(), file2.read(), DummyAlice())
    print "In this modified packet we saw:"
    print p.diff()


#:vim et ts=4
