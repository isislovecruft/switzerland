#!/usr/bin/env python2.5

import sys
import threading
import random
import time
import unittest
import os

sys.path.append(".")
sys.path.append("..")

# for PacketCollector
os.environ["PATH"] += ":../switzerland/client/"

from switzerland.common import util
from switzerland.common import local_ip
from switzerland.client import Alice
from switzerland.client.AliceConfig import AliceConfig
from switzerland.client.AliceLink import LocalAliceLink
from switzerland.server import Switzerland
from switzerland.server.SwitzerlandConfig import SwitzerlandConfig
import socket as s

class PcapPlayback(unittest.TestCase):
  """
  Inherit from this class to create tests by playing back PCAP logs.
  """
  
  def setUp(self):
    self.port = random.randint(17000,18000)
    self.server = Switzerland.SwitzerlandMasterServer(SwitzerlandConfig(port=self.port, keep_threads=True, keep_reconciliators=True, seriousness=seriousness_threshold, allow_fake_ips=True))
    util.ThreadLauncher(self.server.accept_connections).start()

  def tearDown(self):
    del self.server

  def pcap_playback(self, filename1, ip_in_pcap1, filename2, ip_in_pcap2, skew_pcap2, playback_offset=0, keep_archives=False, force_public_ip1=False, force_public_ip2=False):
    ip = local_ip.get_local_ip()
    localhost = "127.0.0.1"
    if ip == localhost:
      print "Can't run system tests without a non-localhost interface!!"
      return 0  

    # We turn the packet filter off, because it would require extra waiting
    # mechanisms for the new-members messages to arrive in time for the
    # filtering mechanism.  NTP is off because we don't need it.  Cleaning has
    # to be off because the timestamps in the pcaps are antique.
    if not force_public_ip1:
      public_ip1 = ip_in_pcap1
    else:
      public_ip1 = force_public_ip1

    client1= Alice.Alice(linkobj=LocalAliceLink,\
        config=AliceConfig(host="localhost", port=self.port, use_ntp=False,\
            do_cleaning=False, seriousness=seriousness_threshold,\
            filter_packets=False, keep_archives=keep_archives,\
            force_public_ip=public_ip1, pcap_playback=filename1,\
            force_private_ip=ip_in_pcap1, logfile=None, pcap_logdir=None))

    if not force_public_ip2:
      public_ip2 = ip_in_pcap2
    else:
      public_ip2 = force_public_ip2

    client2= Alice.Alice(\
        config=AliceConfig(host=ip, port=self.port, use_ntp=False,\
                   do_cleaning=False, seriousness=seriousness_threshold, skew=skew_pcap2,\
                   filter_packets=False, keep_archives=keep_archives,\
                   force_public_ip=public_ip2, pcap_playback=filename2,\
                   force_private_ip=ip_in_pcap2, logfile=None, \
                   pcap_logdir=None))
    time.sleep(2)
    # if we have a negative playback_offset, switch the order of events
    if playback_offset < 0.0:
      playback_offset *= -1
      client1, client2 = client2, client1
    client2.listener.start()
    client2.start()
    time.sleep(playback_offset)
    client1.listener.start()
    client1.start()
    client1.listener.done.wait()
    client2.listener.done.wait()

seriousness_threshold = 0

def main():
  if "-s" in sys.argv:
    pos = sys.argv.index("-s")
    try:
      # unittest does things with argv, so lets get there first :)
      global seriousness_threshold
      seriousness_threshold = int(sys.argv[pos +1])
      print "Setting Debug Seriousness to", seriousness_threshold
      del sys.argv[pos:pos+2]  # deletes 2 args
    except IndexError:
      pass
  unittest.main()


