#!/usr/bin/env python2.5

import unittest
import sys
import os
import threading
import random
import time

import PcapPlayback

class PingTestCase(PcapPlayback.PcapPlayback):
  def testPints(self):
    pcap1="pcaps/illum-ping.pcap"
    ip_in_pcap1="192.168.1.107"
    pcap2="pcaps/tapdance-ping.pcap"
    ip_in_pcap2="192.168.1.135"
    self.pcap_playback(pcap1, ip_in_pcap1, pcap2, ip_in_pcap2, 63.0)
    time.sleep(2)
    flow_pairs, okay, leftovers, forged, dropped = self.server.print_global_flow_table()
    self.assertEqual(flow_pairs,1)
    self.assertEqual(okay,4)
    self.assertEqual(leftovers,0)

if __name__ == "__main__":
  PcapPlayback.main()

