import types
import struct
import socket as s
from binascii import hexlify
from switzerland.common.util import bin2int
from switzerland.common import util

class FlowTuple:
  # just a container for flow fields
  src_ip = 0
  src_port = 1
  dest_ip = 2
  dest_port = 3
  proto = 4

def print_flow_tuple(f):
  "Pretty print the raw binary flow"
  return (s.inet_ntoa(f[0]),bin2int(f[1]), s.inet_ntoa(f[2]), bin2int(f[3]),\
         util.prot_name(bin2int(f[4])))

class Flow:
    """ A Flow is a 5-tuple of source ip:port, destination ip:port and protocol.  """
    timeout = 120 # seconds before a flow can be discarded

    def __init__(self, inbound, src_ip, src_port, dest_ip, dest_port, proto, now, in_circle):
        
        assert type(src_ip)    == types.StringType, 'expecting string src_ip'
        assert type(src_port)  == types.StringType, 'expecting string src_port'
        assert type(dest_ip)   == types.StringType, 'expecting string dest_ip'
        assert type(dest_port) == types.StringType, 'expecting string dest_port'
        assert type(proto)     == types.StringType, 'expecting string proto'
        assert type(now)       == types.FloatType,  'expecting float now'
        self.reported = False # have we told switzerland about the flow?
        self.activity = False # has there been any traffic to report on this flow?
        self.inbound = inbound
        self.src_ip = src_ip
        self.src_port = src_port
        self.dest_ip = dest_ip  
        self.dest_port = dest_port
        self.proto = proto
        self.in_circle = in_circle
        self.time_last_active = now
        self.time_started = now
        self.bytes_transferred = 0
        self.packets_transferred = 0

    def __str__(self):
        (s1, s2, s3, s4) = struct.unpack(">BBBB", self.src_ip)
        (sp,) = struct.unpack('>H', self.src_port)
        (d1, d2, d3, d4) = struct.unpack(">BBBB", self.dest_ip)
        (dp,) = struct.unpack('>H', self.dest_port)
        proto = ord(self.proto)
        if   proto == 1:  proto = 'icmp'
        elif proto == 2:  proto = 'igmp'
        elif proto == 6:  proto = 'tcp'
        elif proto == 17: proto = 'udp'
        elif proto == 132: proto = 'sctp'
        if sp == 65535: sp = 'none'
        if dp == 65535: dp = 'none'
        return "%s.%s.%s.%s:%s -> %s.%s.%s.%s:%s (%s)" % \
            (s1, s2, s3, s4, sp, d1, d2, d3, d4, dp, proto)

