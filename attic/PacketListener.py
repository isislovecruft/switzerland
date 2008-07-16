import threading, thread
import pcapy
import Packet
import FlowManager
import tempfile
import os
import sys
import platform
from binascii import hexlify
import struct
if platform.system() != 'Windows':
    import posix
import subprocess
import Alice
import logging

double_check = True
if double_check:
  import scapy
  pcount = 0

log = logging.getLogger('alice.packet_listener')

class PacketListener(threading.Thread):
    """ sniff incoming IP datagrams on a network interface or from a save file.
        pass packets off to FlowManager. """

    def __init__(self, parent, skew=0.0):
        """ flow_manager: FlowManager to receive packets
            flow_cv: condition variable to notify reporting thread when batches full """
        threading.Thread.__init__(self)
        self.parent = parent
        self._tempfile = None
        self._zcat = None
        self._live = None
        self._skew = skew
        self._reader = None
        self.hash_key = None
        self.frag_warn = False # have we warned about fragmented packets?
        self.done = threading.Event() # are we done replaying an offline capture?

    def run(self):
        """ sit in a tight loop and collect packets
            in interactive mode, run until the parent thread exits.
            in offline mode, break when the dump file ends """
        while True:
            if self.collect() == 0 and self._live == False:
                break

        # close pipe from zcat for gzipped traces
        if self._zcat != None:
            self._zcat.wait()
        if self._tempfile != None:
            os.unlink(self._tempfile)

        # notify parent thread that there's no more input
        self.done.set()

    def open_offline(self, filename):
        """ read packets from saved dump
            filename: path to dump file """
        self._live = False

        # pcapy can't deal with gzipped input
        if filename.endswith('.gz'):
            trim_gz = filename[:-3]

            # if there's an ungzipped copy in the same place, use it
            if os.path.exists(trim_gz):
                filename = trim_gz

            # XXX this isn't going to work on windows
            elif platform.system() == 'Windows':
                print "sorry, I don't know how to open gzipped traces on windows"
                print "please gunzip %s and try again\n" % (filename)
                raise NotImplementedError

            # use a named pipe if we got em
            else:
                tmp = tempfile.mktemp()
                posix.mkfifo(tmp)

                self._zcat = subprocess.Popen('zcat "%s" > "%s"' % (filename, tmp), shell=True)
                self._tempfile = tmp
                filename = tmp
            
        self._reader = pcapy.open_offline(filename)
        self._reader.setfilter('ip')

    def old_open_live(self, interface, promiscuous = False, time_to_poll = 10):
        """ read packets from network interface
            interface: interface to read from
            promsicuous: open interface in promiscuous mode?
            time_to_poll: ms before yielding control (unreliable) """
        self._live = True
        self._reader = pcapy.open_live(interface, 65535, promiscuous, time_to_poll)
        self._reader.setfilter('ip')

    def open_live(self, iface):

        tmp = tempfile.mktemp()
        posix.mkfifo(tmp)
        sniff = subprocess.Popen('tcpdump -p -s 100 -i %s -w - ip > %s' % (iface, tmp),shell=True)
        self._reader = pcapy.open_offline(tmp)

    def broken_open_live(self, iface):

        tmp = tempfile.mktemp()
        posix.mkfifo(tmp)
        sniff = subprocess.Popen('TcpdumpBuffer.py %s > %s' % (iface, tmp),shell=True)
        self._reader = pcapy.open_offline(tmp)

    def collect(self):
        """ collect packets from interface or log
            returns whenever a new packet is available or an error has occurred """
        assert self._reader != None, 'expecting reader to exist'
        def enqueue(header, data):
            if double_check:
              global pcount
              p = scapy.Ether(data)
              try:
                ipid = struct.pack("!H", p.id)
              except AttributeError:
                print "FAILED to get scapy IPID for", p.show()
                pcount += 1
                return
              self.parent.fm.scapy_ipids[ipid] = p
              if pcount % 1000 == 0:
                print "Packet #" + `pcount`, p.show()
              pcount += 1

            try:
              packet = Packet.Packet(
                header.getts()[0] + header.getts()[1]/1000000.0 + self._skew,
                data, 
                self.parent
              )
            except:
              log.warn("Packet parser failed on the following packet:\n%s\n%s\n"\
                       % (scapy.Ether(data).show(), hexlify(data)) )
              raise
              #print "HELP I'M STUCK IN AN EXCEPTION HANDLER"
              #return
              
            if double_check:
              assert packet.ipid == ipid, "%s != %s" % (`packet.ipid`, `ipid`)
            if packet.is_fragment(): #skip fragmented packets
                if not self.frag_warn:
                    log.warn("We saw fragments! This may result in false drop reports.")
                    self.frag_warn = True
                return
            self.parent.fm.batch_to_process.acquire()
            # notify reporter thread if this packet completes a batch
            if self.parent.fm.handle_packet(packet):
                self.parent.fm.batch_to_process.notify()
            self.parent.fm.batch_to_process.release()
        return self._reader.dispatch(-1, enqueue)

