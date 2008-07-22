#!/usr/bin/env python2.5
import time
import os
import os.path
import threading
import types
import logging
import struct

log = logging.getLogger()

class LoggerError(Exception):
  pass


class PcapWriter():
  "Write some packets to a pcap file"
  def __init__(self, path):

    magic = 0xa1b2c3d4L
    majv = 2
    minv = 4
    timewarp = 0
    sigfigs = 0 # Get this from the reconciliator?  Tricky because there 
                # are significant figures relative to real time and 
                # significant figures relative to other packes. we really
                # should ask each client's NTP for the clock jitter...
    snaplen = 1600
    linktype = 1  # XXX FIXME

    hdr = struct.pack("@IHHIIII", magic, majv, minv, timewarp, sigfigs,
                                                           snaplen, linktype)
    self.file = open(path, "w")
    self.file.write(hdr)

  def write(self, packet, timestamp):
     sec = int(timestamp)
     usec = int((timestamp - sec)*1000000)
     length = len(packet)
     pkthdr = struct.pack("@IIII", sec, usec, length, length)
     self.file.write(pkthdr)
     self.file.write(packet)


class PcapLogger():
  """
  This device organises the elaborate switzerland logging structure, which
  is a standard log containing references to a directory of incident-specific
  pcap log files.
  """
  
  # XXXXXX fix this default before release
  def __init__(self, log_dir):
    self.lock = threading.RLock()
    self.make_or_check_directory(log_dir, "log dir")
    ts = self.timestamp()
    self.log_dir = log_dir     
    # XXX do not expect this to be secure if log_dir is world writeable
    # on a multi-user system
    self.make_or_check_directory(self.log_dir, "pcap log dir")
 
  def make_or_check_directory(self, path, alias="directory"):
    alias += " "
    try:
      os.mkdir(path, 0755)
    except OSError:
      assert not os.path.islink(path), alias + path + " should not be a symlink!"
      assert os.path.isdir(path), alias + path + "is not a directory"

  def new_flow(self, flow, id):
    log.info("New bidirectional flow %d : %s\n" % (id,`flow`))

  def timestamp(self, t=None):
    if t == None:
      t = time.time()
    frac = `t - int(t)`[2:5]
    return time.strftime("%Y%m%d%H%M%S", time.localtime(t)) + frac

  def log_forged_in(self, context, id):
    self.lock.acquire()
    try:
      in_path, out_path = self.__gen_filenames(context)
      pcap = PcapWriter(in_path)
      self.log_to_pcap(context, pcap)
      pcap.file.close() 
    finally:
      self.lock.release()
    return out_path

  def log_forged_out(self, context, out_path):
    self.lock.acquire()
    try:
      pcap = PcapWriter(out_path)
      self.log_to_pcap(context, pcap)
      pcap.file.close() 
    finally:
      self.lock.release()

  def __gen_filenames(self, context):
    "Determine the filenames for the inbound and outbound logs"

    ts = self.timestamp(context[0][0])
    filename1 = ts + "-in.pcap"
    filename2 = ts + "-out.pcap"
    path1 = self.log_dir + os.path.sep + filename1
    path2 = self.log_dir + os.path.sep + filename2
    n = 0
    while os.path.exists(path1):
      # This inbound filename has already been used; find another
      filename1 = ts + "-"  + `n` + "-in.pcap"
      filename2 = ts + "-"  + `n` + "-out.pcap"
      path1 = self.log_dir + os.path.sep + filename1 
      path2 = self.log_dir + os.path.sep + filename2 
      n +=1
    log.info("Recording inbound modified packets & context in %s\n" % path1)

    return (path1,path2)
    
  def log_to_pcap(self, packets, pcap_log):
    ## consider adding linktype= to this:

    for timestamp, hash, packet in packets:
      # be careful what we feed to scapy!
      if type(packet) != types.StringType:
        raise LoggerError, "Packet data %s is not a string!\n" % packet

      try:
        pcap_log.write(packet,timestamp)
      except:
        log.error("Tripped on %s", `pcap_log`)
        raise
      pcap_log.file.flush()

if __name__ == "__main__":
  l = PcapLogger("/var/log/switzerland/")
  logging.basicConfig()
  log = logging.getLogger()
  log.setLevel(logging.DEBUG)
  l.log_forged_in([(2,"0x0x", "yjfoisjfoidsjfseehayee"), (3,"0y0y", "yejsidofjsoidhooyee")], 1)
