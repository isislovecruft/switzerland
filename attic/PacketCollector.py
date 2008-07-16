#!/usr/bin/env python2.5

# This code runs in a separate process so that we do our best to ask
# the OS for sniffed packets on a timely basis.  The OS has a tendency
# to drop them otherwise...

import socket
from binascii import hexlify
import sys
import struct
import os
import pcap
import subprocess
import time

# Packet entries current look something like this:
#typedef struct packet_entry {
#  uint8_t valid;
#  uint8_t padding;
#  uint16_t packet_length;
#  uint32_t padding2;
#  double timestamp;
#  char data[MAX_PACKET_SIZE];
#} PacketEntry;

packet_size = 1600 
# an unsigned int for the packet size, and a double for the timestamp
valid_size = 1
packlen_size = struct.calcsize("H")
ts_size = struct.calcsize("d")
padding = 5
entry_size = packet_size + packlen_size + ts_size + valid_size + padding
assert (entry_size % 8) == 0, "expecting entries 8B aligned, got %s"%(entry_size)
packets = 25000
buffer_size = packets * entry_size

class PacketCollector():
  
  def __init__(self):
    """
    Create an mmaped buffer that we can use to efficiently transfer
    packets to the Switzerland client with buffering.
    """
    import tempfile
    import mmap
    try:
      self.file, self.filename = tempfile.mkstemp()
      init = "\x00" * buffer_size
      assert os.write(self.file, init) == buffer_size
    except:
      print "Failure to create tmp buffer of size", buffer_size, ":"
      raise
    self.mem = mmap.mmap(self.file, buffer_size, access=mmap.ACCESS_WRITE)
    self.pos = 0
    # print the mmap filename so that our parent can also mmap it
    sys.stdout.write("Tempfile: "+ self.filename +"\n")
    sys.stdout.flush()

  def cleanup(self):
    """
    Close all our file descriptors; shred the packet logs that might
    otherwise remain on the disk; delete the buffer file.
    """
    self.mem.close()
    os.close(self.file)
    # don't delete the file, since our parent wants to shred it:
    # os.unlink(self.filename)
    return

  def buffer_write(self, pkt, timestamp):
    "Copy this packet to the mmap()ed buffer."
    if self.mem[self.pos] != '\x00':
      # Oh dear, the field we want to write in has a packet in it
      print "ERROR: FAILED TO KEEP BUFFER FROM OVERFLOWING"
      print "(After capturing %d packets)"% self.count
      sys.stderr.write("ERROR: FAILED TO KEEP BUFFER FROM OVERFLOWING\n")
      sys.stderr.write("(After capturing %d packets)\n"% self.count)
      self.cleanup()
      sys.exit(1)
    if len(pkt) > packet_size:
      # This is possible a sign of TCP large segment offloading, which is
      # basically an error condition for Switzerland...
      sys.stderr.write("ERROR: Cannot handle packet of length %d\n"%len(pkt))
      sys.stderr.write(hexlify(pkt) +"\n")
      self.cleanup()
      sys.exit(1)

    self.pos += valid_size + 1 # 1 byte padding
    # write the "valid" byte last

    self.mem[self.pos:self.pos+packlen_size] = struct.pack("H", len(pkt))
    self.pos += packlen_size + 4 # XXX nonportable: 4 bytes padding
    self.mem[self.pos:self.pos+ts_size] = struct.pack("d", timestamp)
    self.pos += ts_size

    # XXX YUCK.  The mmap slice assignment method incorrectly refuses to
    # accept a buffer as an argument.  The write() method probably won't have
    # this problem, so there is an alternative with write()s and occasional
    # seek()s that is probably faster...
    self.mem[self.pos:self.pos+len(pkt)] = str(pkt)

    # then rewind and mark the packet valid
    self.pos -= packlen_size + ts_size + valid_size + 5
    self.mem[self.pos] = '\xff'

    self.pos = (self.pos + entry_size) % buffer_size
  
  def pypcap_sniff(self, iface="any"):
    "Loop, collecting packets."
    pc = pcap.pcap(iface, promisc=False)
    pc.setfilter("ip")
    try:
      pc.stats()
      live = True
    except OSError:
      # this isn't a live capture; it's a pcap playback
      live = False

    print pc.datalink()

    self.count = 0
    # This is an infinite for loop unless we're actually reading from
    # a pcap file
    for timestamp, packet in pc:
      self.buffer_write(packet,timestamp)
      self.count +=1
      if not live:
        # limit playback to a reasonable speed
        time.sleep(0.001)
      else:
        # check the OS hasn't dropped anything
        if self.count % 10 == 0:
          total, dropped, if_dropped = pc.stats()
          if dropped:
            sys.stderr.write("ERROR: %d PACKET(S) OF %d OUTDROPPED BY OS\n" % (dropped, total))
            self.cleanup()
            sys.exit(1)

    print "count was", self.count
    try:
      self.cleanup()
    except:
      pass
    sys.exit(0)

if __name__ == "__main__":
  try:
    import psyco
    psyco.full()
  except ImportError:
    pass
  s = PacketCollector()
  iface=sys.argv[1]

  s.pypcap_sniff(iface=iface)
