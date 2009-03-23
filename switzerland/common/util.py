# Handy routines for Switzerland

import binascii
import os
import platform
import random
import string
import sys
import time
import traceback
import threading
import array
import logging

log = logging.getLogger('util')


# FIXME: It is perhaps best to move the PROTOCOLS dict to a separate file. Note
# that doing so will require the function prot_name to be updated.

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



if platform.system() == 'Windows':
    try:
        import win32api, win32process, win32con
    except:
        print 'Please install the python win32 extensions'
        print '(see INSTALL.txt for details)'
        sys.exit(1)

class DebugMe(Exception):
    pass

def writable(path):
    try:
        return os.access(path, os.W_OK)
    except AttributeError:
        # http://docs.python.org/library/os.html claims availability of
        # os.access on both Unix and Windows. For any other exotic operating
        # systems, the following hack may work.
        try:
            import tempfile
            f = tempfile.TemporaryFile(dir=path)
            f.close()
        except OSError:
            return False

        return True

def prot_name(prot_num):
  """Called from outside: return the name of a protocol number, if we can."""

  return PROTOCOLS.get(int(prot_num), str(prot_num))

class VersionMismatch(Exception):
    pass

def bin2int(str):
    """Convert a raw string to an int (Yuck!!!)"""

    return int(eval("0x" + binascii.hexlify(str)))

def check_python_version():
    if platform.python_version_tuple() < ['2', '5']:
        raise VersionMismatch('expecting python version 2.5 or later')

def debugger():
    import pdb
    error, value, traceback = sys.exc_info()
    print "Invoking debugger after", error, value
    pdb.post_mortem(traceback)

def screensafe(data_structure):
    """Return a representation of an untrusted data structure that's okay to
    print."""

    str = repr(data_structure)
    if len(str) > 53:
        str = str[:50] + "..."
    return str

def set_win32_priority(pid=None, priority=1):
    """Set The Priority of a Windows Process.
    
    Priority is a value between 0-5 where 2 is normal priority.  Default sets
    the priority of the current python process but can take any valid process
    ID.
    """

    priorityclasses = [win32process.IDLE_PRIORITY_CLASS,
                       win32process.BELOW_NORMAL_PRIORITY_CLASS,
                       win32process.NORMAL_PRIORITY_CLASS,
                       win32process.ABOVE_NORMAL_PRIORITY_CLASS,
                       win32process.HIGH_PRIORITY_CLASS,
                       win32process.REALTIME_PRIORITY_CLASS]
    if pid == None:
        pid = win32api.GetCurrentProcessId()
    handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, pid)
    win32process.SetPriorityClass(handle, priorityclasses[priority])

class ThreadLauncher(threading.Thread):
    def __init__(self, fn, handle_control_c=None, respawn=False):
        "fn is run in its own thread; handle_control_c is a exit callback"
        self.fn = fn
        self.respawn = respawn
        if handle_control_c:
            self.handle_control_c = handle_control_c
        else:
            self.handle_control_c = self.fallback_handler
        threading.Thread.__init__(self)
        self.setDaemon(True)

    def fallback_handler(self):
        sys.stderr.write("Unhandled control-c:\n%s" % traceback.format_exc())

    def run(self):
        try:
          try:
              self.fn()
          except KeyboardInterrupt:
              self.handle_control_c()
        except:
          if self.respawn:
              log.error("Respawning thread after exception:\n%s" % 
                        traceback.format_exc())
              self.fn()
          else:
              raise
          

def hexhex(thing):
    "Coerce an arugment in to hexadecimal, by hook or by crook"
    tries = ""
    try:
        return hex(thing)
    except:
        tries += traceback.format_exc()
    try:
        return binascii.hexlify(thing)
    except:
        tries += traceback.format_exc()
    try:
        return binascii.hexlify(thing.tostring())
    except:
        tries += traceback.format_exc()
        # desperate measures
        msg = "I don't know how to convert a %s (%s) into hex\n" % \
              (`type(thing)`, `thing`)
        #msg += "Attempts:\n" + tries
        raise Exception(msg)
