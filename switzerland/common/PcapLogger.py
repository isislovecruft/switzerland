#!/usr/bin/env python2.5
import time
import os
import os.path
import threading
import scapy  # pcapy wasn't up to writing our pcap files
import types
import logging

log = logging.getLogger()

class LoggerError(Exception):
  pass

class PcapLogger():
  """
  This device organises the elaborate switzerland logging structure, which
  is a standard log containing references to a directory of incident-specific
  pcap log files.
  """
  
  # XXXXXX fix this default before release
  def __init__(self, log_dir="/tmp/switzerland"):
    self.lock = threading.RLock()
    self.make_or_check_directory(log_dir, "log dir")
    ts = self.timestamp()
    self.filebase = log_dir + "/switz-" + ts 
    self.pcap_dir = self.filebase + ".pcaps"
    # XXX do not expect this to be secure if log_dir is world writeable
    # on a multi-user system
    self.make_or_check_directory(self.pcap_dir, "pcap log dir")
 
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
      in_path, out_path = self.__gen_filenames(context, id)
      pcap = scapy.PcapWriter(in_path, gz=0)
      self.log_to_pcap(context, pcap)
      pcap.f.close() 
    finally:
      self.lock.release()
    return out_path

  def log_forged_out(self, context, out_path):
    self.lock.acquire()
    try:
      pcap = scapy.PcapWriter(out_path, gz=0)
      self.log_to_pcap(context, pcap)
      pcap.f.close() 
    finally:
      self.lock.release()

  def __gen_filenames(self, context, id):
    "Determine the filenames for the inbound and outbound logs"

    ts = self.timestamp(context[0][0])
    filename1 = ts + "-in.pcap"
    filename2 = ts + "-out.pcap"
    path1 = self.pcap_dir + "/" + filename1
    path2 = self.pcap_dir + "/" + filename2
    n = 0
    while os.path.exists(path1):
      # This inbound filename has already been used; find another
      filename1 = ts + "-"  + `n` + "-in.pcap"
      filename2 = ts + "-"  + `n` + "-out.pcap"
      path1 = self.pcap_dir + "/" + filename1 
      path2 = self.pcap_dir + "/" + filename2 
      n +=1
    log.info("Recording inbound modified packets & context in %s\n" % path1)

    return (path1,path2)
    
  def log_to_pcap(self, packets, pcap_log):
    ## consider adding linktype= to this:

    for timestamp, hash, packet in packets:
      # be careful what we feed to scapy!
      if type(packet) != types.StringType:
        raise LoggerError, "Packet data %s is not a string!\n" % packet

      #int(timestamp) # like an assertion

      # This cannot be efficient :)
      # PPP is just an arbitrary link layer protocol to use here
      #p = scapy.Ether(dst="00:1d:7e:13:14:15", src="00:1d:7e:44:55:66", type=scapy.ETH_P_IP)
      p = scapy.Ether(packet)
      #p.add_payload(packet)
      p.time = timestamp
      try:
        pcap_log.write(p)
      except:
        log.error("Tripped on %s", `pcap_log`)
        raise
      pcap_log.f.flush()

if __name__ == "__main__":
  l = Logger()
  l.forged_packet([(2,"yjfoisjfoidsjfseehayee"), (3,"yejsidofjsoidhooyee")])
