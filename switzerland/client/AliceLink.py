import sys
import socket as s
import time
import traceback
import logging
from binascii import hexlify

from switzerland.common import Protocol
from switzerland.common import Messages
from switzerland.common import util
from switzerland.client import FlowManager

log = logging.getLogger('alice.link')

class AliceLink(Protocol.Protocol):
  "Extend the protocol base class for Alice's end."

  def __init__(self, quit_event, parent, config):
    self.in_messages = Messages.alice_in_messages 
    self.out_messages = Messages.alice_out_messages
    try:
      self.flow_manager = parent.fm
    except AttributeError:
      self.flow_manager = None
    self.parent = parent
    self.config = config
    self.quit_event = quit_event
    self.dangling_note = False
    self.forged_notification = True

    self.socket = s.socket(s.AF_INET, s.SOCK_STREAM)
    log.info("Connecting to %s:%s", config.host, `config.port`)
    self.socket.settimeout(10.0)
    try:
      self.socket.connect((config.host, config.port))
    except:
      log.error("couldn't connect to %s:%s", config.host, `config.port`)
      sys.exit(1)
    self.socket.settimeout(40)

    self.peer = (config.host, config.port)
    self.member_queue = []  # members to be added once we public_ip is known

    Protocol.Protocol.__init__(self, log, config.seriousness, private_ip=config.private_ip)
    # up until now it has been safe to send messages on the socket because
    # we are still blocking the caller thread

  def run(self):
    try:
      Protocol.Protocol.run(self)
    except:
      print traceback.format_exc()
    self.quit_event.set()
    self.ready.set() # to hurry Alice up

  def handshake(self):
    """Confirm that we are talking to a Switzerland server"""
    
    self.socket.send(Protocol.handshake1)

    self.socket.settimeout(30)
    try:
      msg = self.socket.recv(len(Protocol.handshake2))
    except s.timeout:
      self.debug_note("Timeout during handshake", seriousness=11)
      return False
    except s.error, e:
      log.error("error during handshake: %s" % e)
      return False
    except:
      log.error("error during handshake")
      return False

    if msg[:-2] == Protocol.no_common_version[:-2]:
      log.error("Server refuses to speak protocols before version %d; we need version %d" % (Protocol.parse_version(msg[-2:]), Protocol.protocol_version))
      return False
    
    elif msg[:-2] != Protocol.handshake2[:-2]:
      log.error("Handshake failed, wasn't expecting:\n" + msg)
      return False

    log.debug("Started session with version %d" % Protocol.parse_version(msg[-2:]))
    self.socket.setblocking(1)
    return True

  def setup(self):
    "Handshake successful; now do initial housekeeping"
    self.send_myip()

  def lookup_flow_by_id(self, flow_id, caller):
    """
    Called in handle_forged_{in,out}
    Return the flow, or None if we fail.
    "caller" is modified-{in,out} & is only used for error reporting.
    """
    if flow_id not in self.flow_manager.flow_id_to_address:
      msg = "stale %s flow id %s" % (caller, `flow_id`)
      log.info(msg)
      self.send_message("error-cont", [msg])
      return None

    flow_addr = self.flow_manager.flow_id_to_address[flow_id]
    if flow_addr not in self.flow_manager.flows:
      msg= "bad %s flow addr %s in id to addr dict" % (caller, `flow_addr`)
      log.error(msg)
      self.send_message("error-cont", [msg])
      return None

    flow = self.flow_manager.flows[flow_addr]
    return flow

  def handle_forged_out(self, args, seq_no):
    """ Send context surrounding a forged hash """
    if self.flow_manager == None:
      # we're in a test case
      return
    self.flow_manager.lock.acquire()
    try:
      flow_id, forgeries = args
      log.warn("Switzerland has informed us of %d modified/spoofed outbound packets in flow #%d" % (len(forgeries), flow_id))
      self.forged_note()
      flow = self.lookup_flow_by_id(flow_id, "modified-out")
      self.nat_firewall_warnings(flow)
      contexts = {}
      reports = {}
      for wanted in forgeries:
        hash = wanted[0]             # hash of forged packet 
        receipt_context = wanted[1]
        filename = self.parent.pcap_logger.log_forged_in(receipt_context, flow_id)
        ctxt, report = flow.get_fo_context_and_diff(receipt_context, self.parent)
        if report:
          log.error("Here is what we know about these modified packets:\n%s\n" %
                    fmt_forged_report(report))
          reports[hash] = report
        else:
          log.error("This packet appears to have been injected")
          log.error("(at least, we couldn't find a packet we're sure was modified)")
          log.error("(AND THIS CODE SHOULDN'T RUN)")
        if ctxt:
          contexts[hash] = ctxt
          self.parent.pcap_logger.log_forged_out(ctxt, filename)
        else:
          log.error("No modified-out context for %s" % hexlify(hash))
          contexts[hash] = None
      self.send_message("fo-context", [contexts, reports], reply_seq_no=seq_no)
      
    finally:
      self.flow_manager.lock.release()


  def handle_forged_in(self, args, seq_no):
    """ Send context about forged packets whose batches have exactly
        the newest_timestamps specified in timestamps. """
    self.flow_manager.lock.acquire()
    try:
      try:
        flow_id, packets_wanted = args
        log.warn("Switzerland has informed us of %d modified inbound packets in flow #%d" % (len(args[1]), flow_id))
        self.forged_note()
        flow = self.lookup_flow_by_id(flow_id, "modified-in")
        if not flow or self.nat_firewall_warnings(flow) == -1:
          # errors have already been reported
          return

        contexts = {}
        out_filenames = []
        for ts,hash in packets_wanted:
          context = contexts[hash] = flow.get_fi_context(ts, hash)
          if not context:
            log.warn("No context was available for hash %s" % hexlify(hash))
            out_filenames.append("")
          else:
            fn = self.parent.pcap_logger.log_forged_in(context, flow_id)
            out_filenames.append(fn)

        self.send_message("fi-context", [contexts], reply_seq_no=seq_no,\
                          data_for_reply=out_filenames)
      except:
        log.error("exception in handle_forged_in:")
        log.error(traceback.format_exc())
    finally:
      self.flow_manager.lock.release()

  def forged_note(self):
    """
    Point the user towards some (hopefully) helpful documentation about the
    forged -in and -out PCAPs.  But only do this once!
    """
    if not self.forged_notification:
      log.warn("For information about Switzerland's modified/forged PCAP "+\
               "records, please see") 
      log.warn("http://switzerland.wiki.sourceforge.net/forged")
      self.forged_notification = True

  def nat_firewall_warnings(self, flow):
    """
    Warn the user if they are seeing reports of modified packets when there
    are NAT firewalls along the path, since those NATs are mischievous.
    Return -1 if we encounter & report a fatal error along the way.
    """

    if flow.inbound:
      them = flow.src_ip
    else:
      them = flow.dest_ip
    them_p = s.inet_ntoa(them)
    try:
      peer_firewalled = self.flow_manager.is_peer_firewalled(them)
    except:
      msg = "Can no longer find " + them_p + " in peer records ("
      msg += `self.flow_manager.peers` + ")"
      log.error(msg)
      self.send_message("error-cont", [msg])
      return -1
    if not (peer_firewalled or self.firewalled):
      return
    msg = "(Note that "
    if self.firewalled: 
      msg += "you are behind a NAT firewall"
      if peer_firewalled: 
        msg += " and "
    if peer_firewalled:
      msg += "this other machine (at %s) is behind a NAT firewall" % them_p
    msg += ", so it is likely that these modifications are being made "
    msg += "by firewalls, not ISPs)"
    log.warn(msg)

  def handle_forged_details(self, args, reply_seq_no):
    """
    A "forged-details" message is the followup to for forged-in; it shows 
    us Alice's side of the story.
    """
    meta = args[0]
    in_reply_to, remembered = meta
    id = args[1]
    msgs = args[2]

    if in_reply_to != "fi-context":
      self.protocol_error("reply %d should not be a forged-details message\n" % reply_seq_no)
      sys.exit(0)

    out_filenames = remembered

    for filename, (timestamp, context, report) in zip(out_filenames, msgs):
      if filename:
        # This nonsense ensures we're prettier for the users
        log.error("Report on forged/modified packet:\n%s\n" % \
                  fmt_forged_report(report))
        if context:
          self.parent.pcap_logger.log_forged_out(context, filename)
        else:
          log.error("no outbound context to write to " + filename) 

  def dummy_handle_forged_in(self, args, seq_no):
    "This variant of handle_forged_in is only used for testing"
    self.debug_note("Heard about %d dummy forged packets: %s" % \
                    (len(args[1]), `args[0]`), 2)
    forgeries = args[1]
    contexts = {}
    for timestamp,hash in forgeries:
      contexts[hash] = [(1,"packet1"), (2,"packet2"),(3,"x" + `timestamp`)]
    self.send_message("fi-context", [contexts], reply_seq_no=seq_no)

  def handle_new_members(self, args):
    new_peers = args[0]
    try:
      self.flow_manager.listen_for(new_peers)
    except:
      # it's most likely this is due to an invalid new_peers list
      self.protocol_error("Problem with new-members: %s\n" % new_peers)
      raise

  def handle_farewell(self, args):
    old_peer = args[0]
    try:
      if self.flow_manager:
        self.flow_manager.farewell(old_peer)
    except:
      self.protocol_error("Problem with farwell: %s\n" % old_peer)
      raise

  def send_myip(self):
    "Figure out the local IP address, and send it."
    if self.config.force_public_ip: # if force_public_ip is set, assume this public ip
      self.send_message("my-ip", [[self.private_ip, self.config.force_public_ip]])
    else:
      self.send_message("my-ip", [[self.private_ip]])

  def handle_public_ip(self, args):
    "Switzerland tells alice her publicly visible ip"
    stored_data = args[0]
    log.debug("Switzerland says our public ip is %s", `args[1]`)
    self.public_ip = args[1]
    self.firewalled = self.public_ip != self.private_ip
    log.info("Private IP: %s ; Public IP: %s", `self.private_ip`, `self.public_ip`)
    self.now_ready()

  def handle_dangling_flow(self, args):
    "Switzerland has failed to matchmake our view of this flow with out peers"
    msg = "Switzerland is unable to test flow #%d.  " % args[0]
    if not self.dangling_note:
      msg += "Reasons for this may include:\n"
      msg += " - Modifications to the first packet in the flow (hash 0x%s)\n" % \
             hexlify(args[1])
      # XXX we could make the inclusion of some of these lines conditional on
      # whether the peer is actually firewalled
      msg += " - The flow is not actually with the other Switzerland client\n" 
      msg += "   (it could be with their firewall, another machine on their LAN,\n"
      msg += "   or an impostor)\n"
      msg+=" - Alice and Bob seeing a different packet as the first packet in the\n"
      msg+="   flow (most likely if the flow was active before switzerland started)\n"
    else:
      msg += "(opening hash 0x%s)" % hexlify(args[1])
    log.warn(msg)
    self.dangling_note = True
    # XXX we should also take steps to prevent the flow manager from send sent
    # and recd messages for this flow

  def debug_ip_id(self, args):
    ip_id = args[0]
    print "\n\n\n\n"
    print "Debugging ip_id", hexlify(ip_id)
    print "ip_id table:", self.flow_manager.ip_ids
    #if ip_id in self.flow_manager.scapy_ip_ids:
    #  print "ip_id is in the scapy table:",self.flow_manager.scapy_ip_ids[ip_id]
    
    #else:
    #  print "ip_id is not in scapy table"
    try:
      print "Found:", hexlify(self.flow_manager.ip_ids[ip_id])
    except:
      print "Unable to find ip_id in flow_manager.ip_ids!!!"
    print "\n\n\n\n"

  def now_ready(self):
    if self.member_queue:
      map (self.handle_new_members, self.member_queue)
    Protocol.Protocol.now_ready(self)

  def determine_response(self, msg_type, args, seq_no, reply_seq_no):

    # First look for messages common to Alice & Switzerland
    if Protocol.Protocol.determine_response(self, msg_type, args, seq_no, reply_seq_no):
      return True

    # Okay, that didn't work...
    if msg_type == "forged-in":
      self.handle_forged_in(args, seq_no)
      return True
    elif msg_type == "new-members":
      if self.flow_manager:  # only false in unit tests
        if self.ready.isSet():
          self.handle_new_members(args)
        else:
          self.member_queue.append(args)
      return True
    elif msg_type == "forged-out":
      self.handle_forged_out(args, seq_no)
      return True
    elif msg_type == "forged-details":
      self.handle_forged_details(args, reply_seq_no)
      return True
    elif msg_type == "farewell":
      self.handle_farewell(args)
      return True
    elif msg_type == "debug-ipid":
      self.debug_ip_id(args)
      return True
    elif msg_type == "public-ip":
      self.handle_public_ip(args)
      return True
    elif msg_type == "flow-status":
      log.info(args[0])
      return True
    elif msg_type == "dangling-flow":
      self.handle_dangling_flow(args)
      return True
    else:
      return False

    return True   # Tricksy
   
  def tst(self):
    self.send_message("ping")
    self.send_message("sent", ["flow","time",[1,2,4]])
    time.sleep(1)
    self.send_message("sent", ["flow","time",[1,2,5]])
    time.sleep(2)
    self.send_message("sent", ["flow","time",[1,2,6]])
    self.send_message("ping")
    self.send_message("ping")
    self.send_message("ping")
    self.send_message("signoff")

def fmt_forged_report(report):
  "Turn a report into a pretty string, safely"
  if type(report) == list and len(report) == 1 and type(report[0]) == str:
    return report[0]
  else:
    return `report`
      
class LocalAliceLink(AliceLink):
  "This AliceLink variant is useful for testing."
  def __init__(self, quit_event, parent, config):
    AliceLink.__init__(self, quit_event, parent, config)
    if config.force_private_ip:
      self.private_ip = config.force_private_ip
    else:
      self.config.private_ip = "127.0.0.1"
      self.private_ip = "127.0.0.1"

