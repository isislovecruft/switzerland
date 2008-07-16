#!/usr/bin/env python2.5

import unittest
import sys
import threading
import random
import time

import PcapPlayback

class ComplexBitTorrentTestCase(PcapPlayback.PcapPlayback):
  def testScalability(self):
    pcap1="pcaps/tapdance-mysterious.pcap"
    ip_in_pcap1="192.168.1.135"
    pcap1_public_ip="67.180.251.11"
    pcap2="pcaps/tbird4-mysterious.pcap"
    ip_in_pcap2="64.147.188.24"
    pcap2_public_ip="64.147.188.24"
    #self.pcap_playback(pcap1, ip_in_pcap1, pcap2, ip_in_pcap2, -2.0, 20)
    self.pcap_playback(pcap1, ip_in_pcap1, pcap2, ip_in_pcap2, 0.0, keep_archives=True, force_public_ip1=pcap1_public_ip, force_public_ip2=pcap2_public_ip)
    time.sleep(12)
    self.server.judgement_day()
    flow_pairs, okay, leftovers, forged, dropped = self.server.print_global_flow_table()
    print "ok=%d forged=%d dropped=%d"%(okay,forged,dropped)
    #self.assertEqual(forged, 8)
    #self.assertEqual(dropped, 1)
    #FlowManager.crawl_archives()
    #print FlowManager.archives
    #self.server.log.f.close()
    #time.sleep(1000)

if __name__ == "__main__":
  #import psyco
  #psyco.full()
  PcapPlayback.main()
