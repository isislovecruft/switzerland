#!/usr/bin/env python

from binascii import hexlify, unhexlify
import socket as s     # make all the constants less crazy
import threading, thread
import sys
import logging
from copy import copy
import types
import time
import traceback
from switzerland.lib import tweaked_cerealizer as cerealizer
from switzerland.common import util
from switzerland.common import Messages
from switzerland.common import local_ip

fo_context_max = 10 # maximum forged packet candidates in forged out context
fi_context_before = 1 # packets before forgery to send with a fi-context reply
fi_context_after = 1 # packets after forgery to send with a fi-context reply
fi_context_cutoff_time = 10 # maximum time after forgery to consider relevant for fi-context reply
hash_length = 6
class Protocol(threading.Thread):
  "Both Alice and the Switzerland server inheret their Link classes from this."

  def __init__(self, log, seriousness=0, accounting=True, private_ip=False):
    """Alice will connect to a server here, Switzerland will get a socket from
    a listening SwitzerlandMasterServer"""

    self.seriousness_threshold=seriousness
    self.accounting = accounting
    self.log = log
    if private_ip:
      log.debug("Setting private IP to %s" % private_ip)
      self.private_ip = private_ip
    else:
      self.private_ip = local_ip.get_local_ip()

    self.ready=threading.Event() # ready for the sender thread, currently set
                                 # after we know if we're firewalled or not 

    self.sequence_no = 0  # sequence number for sent messages

    # this is a lock for data that's shared between read and write threads
    self.status_lock = threading.RLock()
    self.bailing_out = False
    self.bailout_waiting = None     # if we get a bailout during handshake
    self.closed = False
    self.messages_in = 0
    self.messages_out = 0
    self.in_log = []
    self.out_log = []
    self.faking = False

    self.hash_length = hash_length
    
    # For handling acknowledgement messages and replies (which basically
    # count as acks for most purposes)
    self.ack_lock= threading.RLock()
    self.timeout_period = 25   # the time we'll wait for an ack/reply
    self.ack_timeouts = []     # ordered list of (deadline, sequence_no, msg_type)
    self.expected_acknowledgments = {}   # callbacks for failed acks
    self.last_deadline = 0               # the last ack deadline around
    self.last_sent = time.time()

    # this dict passes state from an outbound message that expects a reply
    # to the handler for the inbound reply:
    self.reply_data_table = {}

    threading.Thread.__init__(self)

  # called when the thread starts
  def run(self):
    # minimal pre-cerealize handshake
    if not self.handshake():
      self.free_resources()
      self.close()
      return
    # figure out firewalling, establish circles, etc
    self.sockfile = self.socket.makefile()
    self.setup()
    # This thread will now go and listen for arbitary messages
    self.listen()

  def listen(self):
    "Loop in a thread to receive messages."
    try:
      while True:
        try:
          msg = cerealizer.load(self.sockfile)
          if self.accounting:
            self.accounting_in(msg)
          self.process_inbound_message(msg)
        except cerealizer.EndOfFile:
          self.log.info("Session with %s closed by other side.", self.peer)
          self.close() ; self.free_resources()
          return 0
        except AttributeError:
          # this will be raised if a sender thread has closed our socket
          self.log.info("Connection shutdown by peer.")
          val = traceback.format_exc() 
          if "NoneType" not in val or "recv" not in val:
            # but in this case, that wasn't the exception
            self.debug_note("Not staying quiet about %s" % val, seriousness=0)
          #
          self.status_lock.acquire()
          try:
            if self.closed:
              self.debug_note("Session with "+`self.peer`+" closed by other thread.")
              self.free_resources() ; return 0
          finally:
            self.status_lock.release()
          raise
        except s.error,e:
          self.debug_note("socket error %r" % e)
          self.free_resources() ; self.close()
          if "Interrupted" in "%r" % e:
            # This seems to be a path for control-c
            sys.exit(0)
          return 0
        except:
          # This is weird, but the return 0 above seems to trigger
          # this handler; we want to avoid that
          type,value = sys.exc_info()[0:2]
          if type != SystemExit:
            self.debug_note("Session with " + `self.peer` + " closing on" +\
                            " exception:" + `type` + " " + `value`)
            self.free_resources() ; self.close()
            raise
    except:
      self.debug_note("last exception branch")
      # Every branch should have freed things by now!
      #self.free_resources()
      raise


  def send_message(self, msg_type, arguments=[], missing_ack_callback=None,
    data_for_reply=None, reply_seq_no=None):
    """
    callback is used for failed acknowledgements; data will be passed as
    the first argument to the handler at our end for the replies to messages
    that have expect_reply=True
    """
    
    # Elaborate argument checking
    try:
      assert type(msg_type) == types.StringType, \
      "msg_type should be a string not a %s" % `type(msg_type)`
    except:
      self.log.error("send_message() for non string %s w/ %s", `msg_type`,`arguments`)
      self.bailout("Internal error")
      raise

    # a sequence number magically becomes the first argument if it is required
    m = self.out_messages[msg_type]

    # we have to acquire this early to guarantee sequence_no consistency

    self.status_lock.acquire()
    try:
      if self.closed:
        return False  # this would cramp our style

      # hold status_lock to prevent another thread 
      # from closing socket before send

      if m.expects_ack:
        arguments = [self.sequence_no] + arguments
        self.register_ack(missing_ack_callback, msg_type)
        self.sequence_no +=1
      elif m.expects_reply:
        arguments = [self.sequence_no] + arguments
        # keep this around for the reply handler 
        self.reply_data_table[self.sequence_no] = (msg_type, data_for_reply)
        self.sequence_no +=1

      # a reply sequence number is similar to a sequence number; if both are 
      # required at some point, the reply sequence number will come first
      if m.is_reply:
        arguments = [reply_seq_no] + arguments
      else:
        assert reply_seq_no == None, "Shouldn't have a reply_seq_no for a message (%s) that isn't a reply" % msg_type

      # Elaborate argument checking cont'd
      try:
        assert len(arguments) == m.length - 1,"Sending %s: wanted %d args, have %d : %s" % (msg_type, m.length - 1, len(arguments), arguments)
      except:
        self.log.error("send_message() wrong # of arguments for %s (%s), should be %d", `msg_type`, `arguments`, m.length)
        self.bailout("Internal error")
        raise

      msg = [msg_type] + arguments
      # Hooray. Send the message.
      if msg_type == "sent" or msg_type == "recd":
        # these messages contain _huge_ data blobs.  Print them in hex!
        self.debug_note("Sending %s" % repr(msg[:-1] + [hexlify(msg[-1])]))
      else:
        self.debug_note("Sending %s" % repr(msg))
      cerealizer.dump(msg, self.sockfile)
      self.sockfile.flush()
      if self.accounting:
        self.accounting_out(msg)
      self.last_sent = time.time()
    finally:
      self.status_lock.release()

  def time_since_contact(self):
      return time.time() - self.last_sent

  def process_inbound_message(self, msg):
    """
    First stage for handling an inbound message: check that it's a known
    message type, and that the number of arguments is correct; extract
    sequence numbers, send an ack if its required, if the message is a reply,
    retrieve any state that was stored when we sent the previous message.
    Actual functional message handling is organised by .determine_response()
    """
    
    self.debug_note("Processing inbound %s" % msg, seriousness=-2) 
    # All Switzerland messages should be lists
    if type(msg) != types.ListType or type(msg[0]) != types.StringType or \
      msg[0] not in self.in_messages:
      self.protocol_error("Invalid message object " + util.screensafe(str))

    # Message is a list of: msg_type, [reply_seq_no,] [seq_no,] arguments
    msg_type = msg[0]
    m = self.in_messages[msg_type]
    if len(msg) != m.length:
      self.protocol_error("Invalid message length %d for %s:\n " % \
      (len(msg), util.screensafe(msg)))

    args = []
    offset = 1 
    seq_no = reply_seq_no = None
    if m.is_reply:
      reply_seq_no = int(msg[offset])
      offset += 1
      # semi-magically arrange for the reply data stored at our end to be passed
      # to the handler as if it was sent by the other party
      try:
        reply_data = self.reply_data_table[reply_seq_no]
      except:
        raise
      del self.reply_data_table[reply_seq_no]
      args.append(reply_data)
    if m.expects_ack or m.expects_reply:
      seq_no = int(msg[offset])
      offset += 1

    args += msg[offset:]

    # The rest depends on the specific message
    if not self.determine_response(msg_type, args, seq_no, reply_seq_no):
      sys.stderr.write(
          "Bug in %s.determine_response(), can't handle message %s\n" %
          (`self.__class__`, `(msg_type, args, seq_no, reply_seq_no)`))
      sys.exit(1)

    # Ack at the end to ensure it isn't over-confident
    if m.expects_ack:
      self.send_message("ack", [seq_no])

  def handle_error_bye(self, args):
    # XXX this should do more cleanup on the Switzerland side, at least...
    error = args[0]
    #if type(error) == str:
    #  error = "\n".join([repr(part) for part in error.split("\n")])
    #else:
    error = repr(error)
    #self.log.error("Received error from %s: %s" % (`self.peer`,error))
    print "Received error from %s: %s" % (`self.peer`,error)
    self.free_resources()
    self.close()
    thread.exit()

  def determine_response(self, msg_type, args, seq_no, reply_seq_no):
    """
    Message has been parsed, now work out what to do.
    AliceLink and SwitzerlandLink extend this method.
    Return True if it's been handled, to help inheritor classes.
    """

    if msg_type == "ack":
      self.process_ack(args[0])
    elif msg_type == "ping":
      # XXX perhaps pings should interrogate other threads to make sure none
      # of them are stuck
      pass
    # XXX should these call socket.shutdown() instead?
    elif msg_type == "error-bye":
      self.handle_error_bye(args)
    elif msg_type == "error-cont":
      self.log.error("Error report from peer %s: %s" % (self.peer,`args`))
    elif msg_type == "signoff":
      self.close()
      thread.exit()
    else:
      return False
    
    return True     # tricksy

  def register_ack(self, callback, msg_type):
    "Organise to understand the ack when it arrives."
    self.ack_lock.acquire()
    deadline = time.time() + self.timeout_period
    if deadline < self.last_deadline:
      self.debug_note("Deadlines are out of order! %f %f" % \
      (deadline, self.last_deadline), seriousness = 2)
    else:
      self.ack_timeouts.append((deadline, self.sequence_no, msg_type))

    self.expected_acknowledgments[self.sequence_no] = callback
    self.ack_lock.release()

  def process_ack(self, seq_no):
    self.debug_note("Received ack for " + `seq_no`)

    self.ack_lock.acquire()

    for n in xrange(len(self.ack_timeouts)):
      deadline, sequence, msg_type = self.ack_timeouts[n]
      if sequence == seq_no:
        del self.ack_timeouts[n:n+1]
        break
    else:
      # XXX it's possible the ack is just too late.  What do we do then?
      self.protocol_error("Unexpected ack %s\n" % seq_no)

    del self.expected_acknowledgments[seq_no]

    self.ack_lock.release()

  def check_ack_deadlines(self):
    "Check for overdue acks."
    while not self.closed:
      time.sleep(13)
      self.ack_lock.acquire()
      try:
        try:
          t = time.time()
          n = 0
          for deadline, seq_no, msg_type in self.ack_timeouts:
            if t < deadline:
              break

            # We're overdue.  Time for a callback
            callback = self.expected_acknowledgments[seq_no]
            if callback:
              callback()
            else:
              self.log.warn("No callback for timed out ack %d (%s)" % \
                           (seq_no, msg_type))
            del self.ack_timeouts[n:n+1]
            del self.expected_acknowledgments[seq_no]
            n += 1
        except:
          self.log.error(traceback.format_exc())
      finally:
        self.ack_lock.release()
    
  def free_resources(self):
    # Links can override this if they need to do any memory freeing stuff
    pass

  def protocol_error(self, string):
    "This may diverge between Alice and Switz in the future."
    self.debug_note("Switzerland protocol error:\n" + string)
    self.status_lock.acquire()
    try:
      self.free_resources()
      self.close()
    finally:
      self.status_lock.release()
    #if sys.exc_info()[0] != None:
    #  raise

  def now_ready(self):
    "Set the ready event, checking for queued bailouts."
    self.status_lock.acquire()
    try:
      if self.bailout_waiting != None:
        self.debug_note("Ready but we have a queued bailout!")
        # The force mechanism ensures that other threads waiting on the ready
        # event do not collide with out bailout error message
        self.bailout(self.bailout_waiting, force=True)
      self.ready.set()
    finally:
      self.status_lock.release()

  def bailout(self, string, force=False):
    "The kind of error the other end should be notified about."
    # First try to notify the other end
    self.debug_note("Bailing out with: %s" % string)
    self.status_lock.acquire()
    try:
      try:
        if not (force or self.ready.isSet()):
          self.debug_note("Not ready for bailout, queueing")
          self.bailout_waiting = string
          return
        # ensure that if things go really pear-shaped, bailouts don't nest
        if not self.bailing_out:
          self.bailing_out = True
          self.send_message("error-bye", [string])
      except:
        sys.stderr.write("Can't even bail out properly!")
        raise
        # our caller should be just about to raise an exception anyway
    finally:
      self.debug_note("lock released")
      self.status_lock.release()

    # now close
    try:
      self.close()
    except:
      # as above, caller should be raising an exception soon
      sys.stderr.write("Can't even close socket!")
      

  def close(self, shutdown=s.SHUT_RDWR):
    "A non-errorful close.  The caller is responsible for deciding how to exit."
    self.status_lock.acquire()
    try:
      if not self.closed:
        self.closed = True
        self.debug_note("close()ing session with " + repr(self.peer))
        try:
          if shutdown != None:
            self.socket.shutdown(shutdown)
        except s.error:
          self.debug_note("This shutdown is inellegant!!!")
        self.socket.close()
        if "sockfile" in self.__dict__:
          self.sockfile.close()
    finally:
      self.status_lock.release()

  def free_resources(self):
    """Called when leaving the listener thread.  Override this to ensure data 
       structure cleanups"""
    pass

  def accounting_in(self, msg):
    "Record complete inbound message statistics for debugging etc"
    self.status_lock.acquire()
    #self.debug_note("Got message: %s" % repr(msg))
    self.messages_in +=1
    self.in_log.append(msg)
    self.status_lock.release()

  def accounting_out(self, msg):
    self.status_lock.acquire()
    #self.debug_note("Sending %s" % repr(msg))
    self.messages_out +=1
    self.out_log.append(msg)
    self.status_lock.release()

  def debug_note(self, string, seriousness=0):
    if seriousness < self.seriousness_threshold:
      return
    # This is informative, but long
    s = `self`   # eg <SwitzerlandLink(Thread-5, initial)>
                 # or <LocalAliceLink(Thread-2, started)>
    # So let's shorten it:
    class_info = s[1:6]
    p1,p2 = s[s.find("("):s.find(")")].split(",")
    no = p1[p1.find("-"):]
    state = p2[1]

    self.log.debug(class_info+no+state + ": " + string)

  def thread_no(self):
    "For arcane testing usage only."
    s = `self`   # eg <SwitzerlandLink(Thread-5, initial)>
    class_info = s[1:6]
    return class_info

# These are the definitions for the protocol components used during the
# handshake.  After the handshake is succesful, we switch to 
# cerealized messages.

# XXX This is completely insane.  Rewrite it using struct.
protocol_version = 3

# Protocol version history:

# 2 -- what we launched with for switzerland 0.0.1 - 0.0.7
# 3 -- introduced in the packet-diff branch: Alice and Bob no longer send the 
#      link layer header, and we write all the log pcaps with ll type 0 (null)

supported_protocol_versions = [protocol_version]
# easier than calling chr() for four separate bytes
binary_version=unhexlify("%04x" % protocol_version)
handshake1 = "WellHello"+ binary_version
no_common_version = "Incompatibl" + binary_version
handshake2 = "Switzerland" + binary_version
default_port = 7778

def parse_version(str):
  "Read a 32 bit binary string, return the int it encodes"
  assert (len(str) == 2), "length should be 2, not " + `len(str)`
  # yuck!
  return util.bin2int(str)

# so the other party can recv() either length
assert len(no_common_version) == len(handshake2)

def hashes_in_batch(batch):
  num_hashes = len(batch)/hash_length
  assert len(batch) % hash_length == 0, \
    "Batch size %d is not a multiple of hash size %d" % (len(batch), hash_length)
  return num_hashes

  
# vim: et ts=2
