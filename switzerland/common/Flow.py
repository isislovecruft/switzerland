import types
import struct
import socket as s
from switzerland.common.util import bin2int
from switzerland.common import util

# Protocol number/name pairs.
# Source: http://www.iana.org/assignments/protocol-numbers
#     (last updated 2008-04-18)
PROTOCOLS = {
    0: 'HOPOPT', # IPv6 Hop-by-Hop Option
    1: 'ICMP', # Internet Control Message
    2: 'IGMP', # Internet Group Management
    3: 'GGP', # Gateway-to-Gateway
    4: 'IP', # IP in IP (encapsulation)
    5: 'ST', # Stream
    6: 'TCP', # Transmission Control
    7: 'CBT', # CBT
    8: 'EGP', # Exterior Gateway Protocol
    9: 'IGP', # any private interior gateway (used by Cisco for their IGRP)
   10: 'BBN-RCC-MON', # BBN RCC Monitoring
   11: 'NVP-II', # Network Voice Protocol
   12: 'PUP', # PUP
   13: 'ARGUS', # ARGUS
   14: 'EMCON', # EMCON
   15: 'XNET', # Cross Net Debugger
   16: 'CHAOS', # Chaos
   17: 'UDP', # User Datagram
   18: 'MUX', # Multiplexing
   19: 'DCN-MEAS', # DCN Measurement Subsystems
   20: 'HMP', # Host Monitoring
   21: 'PRM', # Packet Radio Measurement
   22: 'XNS-IDP', # XEROX NS IDP
   23: 'TRUNK-1', # Trunk-1
   24: 'TRUNK-2', # Trunk-2
   25: 'LEAF-1', # Leaf-1
   26: 'LEAF-2', # Leaf-2
   27: 'RDP', # Reliable Data Protocol
   28: 'IRTP', # Internet Reliable Transaction
   29: 'ISO-TP4', # ISO Transport Protocol Class 4
   30: 'NETBLT', # Bulk Data Transfer Protocol
   31: 'MFE-NSP', # MFE Network Services Protocol
   32: 'MERIT-INP', # MERIT Internodal Protocol
   33: 'DCCP', # Datagram Congestion Control Protocol
   34: '3PC', # Third Party Connect Protocol
   35: 'IDPR', # Inter-Domain Policy Routing Protocol
   36: 'XTP', # XTP
   37: 'DDP', # Datagram Delivery Protocol
   38: 'IDPR-CMTP', # IDPR Control Message Transport Proto
   39: 'TP++', # TP++ Transport Protocol
   40: 'IL', # IL Transport Protocol
   41: 'IPv6', # Ipv6
   42: 'SDRP', # Source Demand Routing Protocol
   43: 'IPv6-Route', # Routing Header for IPv6
   44: 'IPv6-Frag', # Fragment Header for IPv6
   45: 'IDRP', # Inter-Domain Routing Protocol
   46: 'RSVP', # Reservation Protocol
   47: 'GRE', # General Routing Encapsulation
   48: 'DSR', # Dynamic Source Routing Protocol
   49: 'BNA', # BNA
   50: 'ESP', # Encap Security Payload
   51: 'AH', # Authentication Header
   52: 'I-NLSP', # Integrated Net Layer Security  TUBA
   53: 'SWIPE', # IP with Encryption
   54: 'NARP', # NBMA Address Resolution Protocol
   55: 'MOBILE', # IP Mobility
   56: 'TLSP', # Transport Layer Security Protocol using Kryptonet key management
   57: 'SKIP', # SKIP
   58: 'IPv6-ICMP', # ICMP for IPv6
   59: 'IPv6-NoNxt', # No Next Header for IPv6
   60: 'IPv6-Opts', # Destination Options for IPv6
#  61: any host internal protocol
   62: 'CFTP', # CFTP
#  63: any local network
   64: 'SAT-EXPAK', # SATNET and Backroom EXPAK
   65: 'KRYPTOLAN', # Kryptolan
   66: 'RVD', # MIT Remote Virtual Disk Protocol
   67: 'IPPC', # Internet Pluribus Packet Core
#  68: any distributed file system
   69: 'SAT-MON', # SATNET Monitoring
   70: 'VISA', # VISA Protocol
   71: 'IPCV', # Internet Packet Core Utility
   72: 'CPNX', # Computer Protocol Network Executive
   73: 'CPHB', # Computer Protocol Heart Beat
   74: 'WSN', # Wang Span Network
   75: 'PVP', # Packet Video Protocol
   76: 'BR-SAT-MON', # Backroom SATNET Monitoring
   77: 'SUN-ND', # SUN ND PROTOCOL-Temporary
   78: 'WB-MON', # WIDEBAND Monitoring
   79: 'WB-EXPAK', # WIDEBAND EXPAK
   80: 'ISO-IP', # ISO Internet Protocol
   81: 'VMTP', # VMTP
   82: 'SECURE-VMTP', # SECURE-VMTP
   83: 'VINES', # VINES
   84: 'TTP', # TTP
   85: 'NSFNET-IGP', # NSFNET-IGP
   86: 'DGP', # Dissimilar Gateway Protocol
   87: 'TCF', # TCF
   88: 'EIGRP', # EIGRP
   89: 'OSPFIGP', # OSPFIGP
   90: 'Sprite-RPC', # Sprite RPC Protocol
   91: 'LARP', # Locus Address Resolution Protocol
   92: 'MTP', # Multicast Transport Protocol
   93: 'AX.25', # AX.25 Frames
   94: 'IPIP', # IP-within-IP Encapsulation Protocol
   95: 'MICP', # Mobile Internetworking Control Pro.
   96: 'SCC-SP', # Semaphore Communications Sec. Pro.
   97: 'ETHERIP', # Ethernet-within-IP Encapsulation
   98: 'ENCAP', # Encapsulation Header
#  99: any private encryption scheme
  100: 'GMTP', # GMTP
  101: 'IFMP', # Ipsilon Flow Management Protocol
  102: 'PNNI', # PNNI over IP
  103: 'PIM', # Protocol Independent Multicast
  104: 'ARIS', # ARIS
  105: 'SCPS', # SCPS
  106: 'QNX', # QNX
  107: 'A/N', # Active Networks
  108: 'IPComp', # IP Payload Compression Protocol
  109: 'SNP', # Sitara Networks Protocol
  110: 'Compaq-Peer', # Compaq Peer Protocol
  111: 'IPX-in-IP', # IPX in IP
  112: 'VRRP', # Virtual Router Redundancy Protocol
  113: 'PGM', # PGM Reliable Transport Protocol
# 114: any 0-hop protocol
  115: 'L2TP', # Layer Two Tunneling Protocol
  116: 'DDX', # D-II Data Exchange (DDX)
  117: 'IATP', # Interactive Agent Transfer Protocol
  118: 'STP', # Schedule Transfer Protocol
  119: 'SRP', # SpectraLink Radio Protocol
  120: 'UTI', # UTI
  121: 'SMP', # Simple Message Protocol
  122: 'SM', # SM
  123: 'PTP', # Performance Transparency Protocol
  124: 'ISIS over IPv4',
  125: 'FIRE',
  126: 'CRTP', # Combat Radio Transport Protocol
  127: 'CRUDP', # Combat Radio User Datagram
  128: 'SSCOPMCE',
  129: 'IPLT',
  130: 'SPS', # Secure Packet Shield
  131: 'PIPE', # Private IP Encapsulation within IP
  132: 'SCTP', # Stream Control Transmission Protocol
  133: 'FC', # Fibre Channel
  134: 'RSVP-E2E-IGNORE',
  135: 'Mobility Header',
  136: 'UDPLite',
  137: 'MPLS-in-IP',
  138: 'manet', # MANET Protocols
  139: 'HIP', # Host Identity Protocol
# 140-252: Unassigned
# 253: Use for experimentation and testing
# 254: Use for experimentation and testing
# 255: Reserved
}

class FlowTuple:
    """Just a container for flow fields."""

    src_ip = 0
    src_port = 1
    dest_ip = 2
    dest_port = 3
    proto = 4

def print_flow_tuple(f):
    """Pretty print the raw binary flow."""

    return (s.inet_ntoa(f[0]),bin2int(f[1]), s.inet_ntoa(f[2]), bin2int(f[3]),\
           util.prot_name(bin2int(f[4])))

class Flow:
    """A Flow is a 5-tuple of source ip:port, destination ip:port and protocol."""

    timeout = 120 # seconds before a flow can be discarded

    def __init__(self, inbound, src_ip, src_port, dest_ip, dest_port, proto, now, in_circle):
        assert isinstance(src_ip, types.StringType), 'expecting string src_ip'
        assert isinstance(src_port, types.StringType), 'expecting string src_port'
        assert isinstance(dest_ip, types.StringType), 'expecting string dest_ip'
        assert isinstance(dest_port, types.StringType), 'expecting string dest_port'
        assert isinstance(proto, types.StringType), 'expecting string proto'
        assert isinstance(now, types.FloatType),  'expecting float now'

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
        proto = PROTOCOLS.get(ord(self.proto), ord(self.proto))
        if sp == 65535: sp = 'none'
        if dp == 65535: dp = 'none'
        return "%s.%s.%s.%s:%s -> %s.%s.%s.%s:%s (%s)" % \
            (s1, s2, s3, s4, sp, d1, d2, d3, d4, dp, proto)

