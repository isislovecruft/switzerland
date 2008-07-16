#!/usr/bin/env python2.5

import unittest
import sys
import threading
import random
import time

import PcapPlayback

class ComplexBitTorrentTestCase(PcapPlayback.PcapPlayback):
  def testScalability(self):
    pcap1="pcaps/bittorrent-1-local.pcap.gz"
    ip_in_pcap1="69.12.135.165"
    pcap2="pcaps/bittorrent-1-remote.pcap.gz"
    ip_in_pcap2="24.21.38.58"
    self.pcap_playback(pcap1, ip_in_pcap1, pcap2, ip_in_pcap2, 1.0, keep_archives=False)
    time.sleep(20)
    self.server.judgement_day()
    flow_pairs, okay, leftovers, forged, dropped = self.server.print_global_flow_table()
    print "ok=%d forged=%d dropped=%d"%(okay,forged,dropped)
    self.assertEqual(forged, 108)   # this is a best guess
    self.assertEqual(dropped, 1)  
    self.assertEqual(okay, 4257)  
    #FlowManager.crawl_archives()
    #self.server.log.f.close()
    #time.sleep(1000)

if __name__ == "__main__":
  #import psyco
  #psyco.full()
  PcapPlayback.main()
