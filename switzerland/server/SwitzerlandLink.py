import sys
import socket as s
sys.path.append("../src/common")
import switzerland.common.Protocol as Protocol
from switzerland.common import Messages
import threading
import logging

log = logging.getLogger('switzerland.link')

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

    # last_status is used by Switzerland's flow state reporting thread
    self.last_status = []
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

    if len(ips) == 2 and self.parent.config.allow_fake_ips: 
      # alice may specify a public ip she wishes to assume
      peer_host = ips[1]
      self.parent.faking_ip(self, peer_host)
      self.fake_ip(peer_host)
      self.alice_firewalled = ips[0] != ips[1]
    else: 
      if len(ips) == 2:
        # Fake IPs are intended for testing.  Perhaps in the future we'll
        # allow them for clients coming in through Tor, but there are security
        # issues to consider with that
        log.error("DENYING REQUEST FOR A FAKE IP!")
        self.send_message("error-cont", ["Denying request for a fake IP"])
      # but by default, she'll believe switzerland
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
      if "version" in self.params:
        log.info("%s is running on %s" %(`self.peer`, `self.params["version"]`))
    finally:
      self.status_lock.release()

  def get_clock_dispersion(self):
    self.status_lock.acquire()
    try:
      return self.clock_dispersion
    finally:
      self.status_lock.release()

  def handle_fi_context(self, args, seq_no, reply_seq_no):
    """
    A "fi-context" message is in reply to a previous "forged-in" from 
    Switzerland.py
    """
    meta, data = args              # meta is paperwork from our side
                                   # data is from bob
    in_reply_to, remembered = meta

    if in_reply_to != "forged-in":
      self.protocol_error("reply %d should not be a fi-context message\n" %\
      reply_seq_no)
      sys.exit(0)
    
    forgeries, rec = remembered

    msgs = []
    log_filenames = []
    for forgery in forgeries:
      timestamp, hash = forgery
      context = data[hash]
      msgs.append((hash, context)) # by convention the actual forgery
                                   # should be context[0]

      # XXX should we do this later, since Alice is waiting?
      if self.parent.config.logging:
        if not context:
          log.error("Bob couldn't find the original fi packet!")
          log_filenames.append("")
        else:
          # it's a bit tricky to decide what filename to put the logs in,
          # and the inbound and outbound filenames need to match; so we
          # figure them both out here and remember the outbound one for later
          out_filename = self.parent.mm.log.log_forged_in(context, id=rec.id)
          log_filenames.append(out_filename)

    token_for_bob = seq_no
    store = (log_filenames,rec,forgeries,token_for_bob)
    for link, id in rec.src_links:
      link.send_other_message("forged-out", [id, msgs], data_for_reply=store)

  def handle_fo_context(self, args, reply_seq_no):
    meta, data = args
    in_reply_to, remembered = meta
    if in_reply_to != "forged-out":
      self.protocol_error("reply %d should not be a fo-context message\n" %\
      reply_seq_no)
      sys.exit(0)

    filenames,rec,forgeries,token_for_bob = remembered
    msgs = []
    if filenames == []:
      assert not self.parent.config.logging, "Pcap log list empty while logging"
      filenames = [None] * len(forgeries)

    assert len(filenames) == len(forgeries), "Pcap logs do not match forgeries"

    # Alice's handle_forged_out should preserve the order of the forgeries
    for forgery,filename in zip(forgeries, filenames):
      timestamp, hash = forgery
      context = data[hash]
      msgs.append((timestamp, context)) # by convention the actual forgery
                                        # should be context[0]
      if self.parent.config.logging:
        if context:
          self.parent.mm.log.log_forged_out(context, filename)
        else:
          log.info("No meaningful forged out context")

    for link, id in rec.dest_links:
      link.send_other_message("forged-details", [id, msgs], \
                              reply_seq_no=token_for_bob)

  hook_callback = None # overwite if desired
  def hook_handle(self, args, seq_no, reply_seq_no):
    "You can copy this method over some other handler method for debugging."
    self.debug_note("Hook handle w/ %s, %s, %s" % (args, seq_no, reply_seq_no))
    if self.hook_callback:
      # this is a function that can be inserted by test cases
      self.hook_callback(self, args, seq_no, reply_seq_no)

       
  def send_other_message(self, msg, args, **keywords):
    """
    This is a wrapper for Protocol.send_message which is intended to be called
    from some thread other than the one started for this link.  This method is
    responsible for ensuring that this thread can't die along the way, even if
    this link is dead.  Return True if we succeeded, and False if the link
    died.
    """
    try:
      self.send_message(msg, args, **keywords)
      return True
    except:
      log.error("Error sending %s message to %s:\n%s\nArgs: %s" % 
                   (msg, `self.peer`, traceback.format_exc(), args))
      try:
        self.close()
      except:
        log.error("In other link:\n", traceback.format_exc())
      try:
        self.free_resources()
      except:
        log.error("In other link:\n", traceback.format_exc())
      return False


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
      self.handle_fi_context(args, seq_no, reply_seq_no)
      return True
    elif msg_type == "fo-context":
      self.handle_fo_context(args, reply_seq_no)
      return True
    elif msg_type == "parameters":
      self.handle_parameters(args)
      return True
    elif msg_type == "traceroute":
      log.info("received traceroute from %s:\n%s" % (`self.peer`,`args`))
      return True

    # Fallthrough, but is this code slow?
    handler_name = "handle_" + msg_type
    if handler_name in self.parent.__class__.__dict__:
      self.parent.__class__.__dict__[handler_name](self.parent, self, args)
      return True

    return False

