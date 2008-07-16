#!/usr/bin/env python2.5

import unittest
import sys
import threading
import random
import time
import PcapPlayback

class ComplexBitTorrentTestCase(PcapPlayback.PcapPlayback):
  def testScalability(self):
    pcap1="pcaps/mynah.pcap"
    ip_in_pcap1="64.147.188.2"
    pcap2="pcaps/mynah.pcap"
    ip_in_pcap2="192.168.1.102"
    self.pcap_playback(pcap1, ip_in_pcap1, pcap2, ip_in_pcap2, 0.0)
    time.sleep(20)
    #self.server.judgement_day()
    flow_pairs, okay, leftovers, forged, dropped = self.server.print_global_flow_table()
    #self.server.log.f.close()
    #time.sleep(1000)

if __name__ == "__main__":
  PcapPlayback.main()
