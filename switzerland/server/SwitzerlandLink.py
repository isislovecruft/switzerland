import sys
import socket as s
sys.path.append("../src/common")
import switzerland.common.Protocol as Protocol
from switzerland.common import Messages
import threading
import logging

class SwitzerlandLink(Protocol.Protocol):
  def __init__(self, socket, peer_addr, parent=None, seriousness=0):
    self.peer = peer_addr
    self.socket = socket
    self.parent = parent  # A SwitzerlandMasterServer
    self.flow_table = {}
    self.flow_lock = threading.RLock()
    self.params = None
    self.clock_dispersion = 1.0 # it should be less than this!
    self.log = logging.getLogger('switzerland.link')

    # So that methods in the parent class know where to find them:
    self.in_messages = Messages.switzerland_in_messages 
    self.out_messages = Messages.switzerland_out_messages 

    # This will be signalled once all peers have been sent a new-members
    # message about us; otherwise, we might be farewelled before we had
    # fully joined, which would have bad consequences
    self.welcomed = threading.Event()

    Protocol.Protocol.__init__(self, self.log, seriousness)

  def handshake(self):
    """
    Confirm that we are talking to a Switzerland client, with the appropriate
    protocol version
    """
    
    self.debug_note("attempting handshake with %s" % repr(self.peer))
    self.socket.settimeout(30)
    try:
      msg = self.socket.recv(len(Protocol.handshake1))
    except s.timeout:
      self.protocol_error("Timeout before handshake")
      
    if msg[:len(Protocol.handshake1) - 2] != Protocol.handshake1[:-2]:
      self.debug_note("Not the start of a Switzerland session:\n"+Protocol.handshake1[:-2], seriousness=11)
      self.close()
      return False

    incoming_prot_ver = Protocol.parse_version(msg[-2:])

    if incoming_prot_ver not in Protocol.supported_protocol_versions:
      self.socket.send(Protocol.no_common_version)
      self.debug_note("Alice is using unsupported protocol version %d" 
                   % incoming_prot_ver, seriousness=11)
      return False
    self.socket.setblocking(1)
    self.socket.send(Protocol.handshake2)
    self.debug_note("completed handshake with %s" % repr(self.peer))
    return True

  def setup(self):
    "Now talking cerealized python, let's do setup."
    pass

  def free_resources(self):
    "Tell our SwitzerlandMasterServer that we're going away."
    self.parent.link_closed(self)

  def fake_ip(self, ip):
    "For testing purposes"
    # XXX add an ACL
    self.status_lock.acquire()
    try:
      self.peer = (ip, self.peer[1])
    finally:
      self.status_lock.release()

  def handle_myip(self, args, reply_seq_no):
    "The other side has told us their opinion of their own IP address"
    peers_public_host, peer_port = self.peer
    peers_public_host = s.gethostbyname(peers_public_host)
    ips = args[0]
    try:
      self.peers_private_ip = s.gethostbyname(ips[0])
    except:
      self.protocol_error("Invalid peer host:\n %s" % util.screensafe(args[0]))

    if len(ips) == 2: # alice may specify a public ip she wishes to assume
      peer_host = ips[1]
      self.parent.faking_ip(self, peer_host)
      self.fake_ip(peer_host)
      self.alice_firewalled = ips[0] != ips[1]
    else: # but by default, she'll believe switzerland
      peer_host = s.gethostbyname(peers_public_host)
      self.alice_firewalled = peer_host != self.peers_private_ip

    self.send_message("public-ip", [peer_host], reply_seq_no=reply_seq_no)

    # XXX the simultaneous use of fake IPs and Alice's filter_packets=True
    # will break this next message
    self.send_message("new-members", [self.parent.peers_of(self.peer[0])])
    self.parent.joining_circle(self)
    self.now_ready()

  def handle_parameters(self, args):
    self.status_lock.acquire()
    try:
      self.params = args[0]
      assert "clock dispersion" in self.params, "Params w/o clock dispersion"
      self.clock_dispersion = self.params["clock dispersion"]
    finally:
      self.status_lock.release()

  def get_clock_dispersion(self):
    self.status_lock.acquire()
    try:
      return self.clock_dispersion
    finally:
      self.status_lock.release()
    

  def determine_response(self, msg_type, args, seq_no, reply_seq_no):

    # First look for messages common to Alice & Switzerland
    if Protocol.Protocol.determine_response(self, msg_type, args, seq_no, reply_seq_no):
      return True
    
    if msg_type == "test":
      self.debug_note("Got test: %s" % `args`)
      return True
    elif msg_type == "my-ip":
      self.handle_myip(args, reply_seq_no=seq_no)
      return True
    elif msg_type == "sent":
      self.parent.handle_sent_or_recd(self, args, sent=True)
      return True
    elif msg_type == "recd":
      self.parent.handle_sent_or_recd(self, args, sent=False)
      return True
    elif msg_type == "fi-context":
      self.parent.handle_fi_context(self, args, seq_no, reply_seq_no)
      return True
    elif msg_type == "fo-context":
      self.parent.handle_fo_context(self, args, reply_seq_no)
      return True
    elif msg_type == "parameters":
      self.handle_parameters(args)
      return True

    # Fallthrough, but is this code slow?
    handler_name = "handle_" + msg_type
    if handler_name in self.parent.__class__.__dict__:
      self.parent.__class__.__dict__[handler_name](self.parent, self, args)
      return True

    return False

