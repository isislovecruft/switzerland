#!/usr/bin/env python2.5

import unittest
import sys
import threading
import random
import time

from PcapPlayback import PcapPlayback

class SimpleSystemTestCase(unittest.TestCase, PcapPlayback):
  def testTest1DotPcap(self):
    pcap_file="test1.pcap"
    ip_in_pcap1=s.inet_aton("192.168.1.101")
    ip_in_pcap2=s.inet_aton("74.125.19.83")
    self.pcap_playback(pcap_file, ip_in_pcap1, pcap_file, ip_in_pcap2)
    time.sleep(5)
    flow_pairs, okay, leftovers = self.server.print_global_flow_table()
    self.assertEqual(flow_pairs, 4)
    self.assertEqual(okay, 28)
    self.assertEqual(leftovers, 0)

if __name__ == "__main__":
  unittest.main()


