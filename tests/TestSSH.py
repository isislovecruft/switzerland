#!/usr/bin/env python2.5

import unittest
import sys
import threading
import random
import time

import PcapPlayback

class SSHTestCase(PcapPlayback.PcapPlayback):
  def testSSH(self):
    pcap1="pcaps/illum-ssh.pcap"
    ip_in_pcap1="192.168.1.107"
    pcap2="pcaps/tapdance-ssh.pcap"
    ip_in_pcap2="192.168.1.135"
    self.pcap_playback(pcap1, ip_in_pcap1, pcap2, ip_in_pcap2, 63.0)
    time.sleep(5)
    self.server.judgement_day()
    time.sleep(2)
    flow_pairs, okay, leftovers, forged, dropped = self.server.print_global_flow_table()
    self.assertEqual(okay, 49)
    self.assertEqual(dropped, 4)
    self.assertEqual(forged, 0)

if __name__ == "__main__":
  PcapPlayback.main()
