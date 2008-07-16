#!/usr/bin/env python2.5

import unittest
import sys
import threading
import random
import time

import PcapPlayback

class ComplexBitTorrentTestCase(PcapPlayback.PcapPlayback):
  def testScalability(self):
    pcap1="pcaps/singleton-local.pcap"
    ip_in_pcap1="69.12.135.165"
    pcap2="pcaps/singleton-remote.pcap"
    ip_in_pcap2="24.21.38.58"
    self.pcap_playback(pcap1, ip_in_pcap1, pcap2, ip_in_pcap2, 2.0)
    time.sleep(2)
    self.server.global_flow_lock.acquire()
    self.assertEqual(len (self.server.global_flow_table), 1)
    self.server.global_flow_lock.release()
    flow_pairs, okay, leftovers, forged, dropped = self.server.print_global_flow_table()

if __name__ == "__main__":
  PcapPlayback.main()
