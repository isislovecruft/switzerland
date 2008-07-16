#!/usr/bin/env python2.5

import unittest
import sys
import threading
import random
import time
import socket as s


sys.path.append("..")  # hack

from switzerland.common import local_ip
import switzerland.server.Switzerland as Switzerland
from switzerland.server.SwitzerlandConfig import SwitzerlandConfig
Switzerland.ipids_in_matchmaker = True
import switzerland.common.util as util
from switzerland.client.AliceLink import AliceLink, LocalAliceLink
from switzerland.client.AliceConfig import AliceConfig
from switzerland.common import Protocol

class ProtocolTestCase(unittest.TestCase):
  def setUp(self):
    self.ip = local_ip.get_local_ip()
    self.localhost = "127.0.0.1"
    if self.ip == self.localhost:
      print "Can't run testFlowManagement without a non-localhost interface"
      return 0  
    self.port = random.randint(17000,18000)
    self.server = Switzerland.SwitzerlandMasterServer(SwitzerlandConfig(port=self.port, keep_threads=True, logging=False))
    util.ThreadLauncher(self.server.accept_connections).start()
    self.lh_config = AliceConfig(host="localhost", port=self.port)
    self.net_config = AliceConfig(host=self.ip, port=self.port)

  def tearDown(self):
    pass

  def testProtocolBasics(self):
    print 80 * "-"
    print "  testProtocolBasics"
    print 80 * "-"
    client = AliceLink(threading.Event(), None, self.lh_config)
    client.start()
    client.ready.wait()

    server_thread = self.server.threads[-1]  # XXX not safe!!!
    client.send_message("ping")
    client.send_message("test", [1,0,[1,2,4]])
    client.send_message("test", [2,0,[1,2,5]])
    client.send_message("test", [3,0,[1,2,6]])
    client.send_message("ping")
    client.send_message("ping")
    client.send_message("ping")
    time.sleep(1)
    client.send_message("signoff")
    time.sleep(1)

    #print "Server in:"
    #print "\n".join(map(repr, server_thread.in_log))
    server_thread.status_lock.acquire()
    # adding one for the firewall mss now in Protocol.setup(), and one more
    # for the default new-members message in Switzerland.new_link() and its
    # ack
    
    self.assertEqual(server_thread.messages_in, 8+2)
    self.assertEqual(server_thread.messages_out, 4+2)  # just for the pings
    self.assert_(server_thread.closed)
    self.assertEqual(client.messages_out,8+2)
    self.assertEqual(client.messages_in,4+2)
    self.assert_(["test", 3, 0, [1,2,6]] in client.out_log)
    self.assert_(["test", 3, 0, [1,2,6]] in server_thread.in_log)
    if local_ip.get_local_ip() != "127.0.0.1":
      #self.assert_(['you-are-firewalled', 0, '127.0.0.1'] in server_thread.out_log)
      #self.assert_(['you-are-firewalled', 0, '127.0.0.1'] in client.in_log)
      self.assert_(['public-ip', 0, '127.0.0.1'] in server_thread.out_log)
      self.assert_(['public-ip', 0, '127.0.0.1'] in client.in_log)
    server_thread.status_lock.release()

  def testFirewallDetection(self):
    print 80 * "-"
    print "  testFirewallDetection"
    print 80 * "-"
    client1 = LocalAliceLink(threading.Event(), None, self.lh_config)
    client1.start()
    client1.ready.wait()
    client1.send_message("ping")
    server_thread1 = self.server.threads[-1]  # XXX not safe!!!
    client2 = LocalAliceLink(threading.Event(), None, self.lh_config)
    client2.start()
    client1.send_message("ping")
    client2.ready.wait()
    time.sleep(1)
    client1.send_message("ping")
    time.sleep(1)
    client1.send_message("ping")
    server_thread2 = self.server.threads[-1]
    self.assertNotEqual(server_thread1,server_thread2)
    self.assert_(['public-ip', 0, '127.0.0.1'] in server_thread1.out_log)
    self.assert_(['public-ip', 0, '127.0.0.1' ] in client1.in_log)
    self.assert_(['public-ip', 0, '127.0.0.1'] in server_thread2.out_log)
    self.assert_(['public-ip', 0, '127.0.0.1'] in client2.in_log)
    self.assert_(['error-bye', 'Too many simultaneous connections from the one IP!'] in server_thread2.out_log)
    self.assert_(['error-bye', 'Too many simultaneous connections from the one IP!'] in client2.in_log)

  def random_flow(self, ip1="55.66.77.88", ip2="11.22.33.44"):
    import binascii
    port = random.randint(1,10000)
    port_s = binascii.unhexlify("%04x" % port)  # encode as raw string
    port2 = random.randint(1,10000)
    port2_s = binascii.unhexlify("%04x" % port2)  
    prot = random.randint(1,20)
    prot_s = binascii.unhexlify("%04x" % prot)
    flow = (s.inet_aton(ip1), port_s, s.inet_aton(ip2), port2_s, prot_s)
    return flow

  def testFlowManagement(self):
    print 80 * "-"
    print "  testFlowManagement"
    print 80 * "-"
    client1 = LocalAliceLink(threading.Event(), None, self.lh_config)
    client1.start()
    client1.ready.wait()
    client1.send_message("ping")
    flow1 = self.random_flow(self.localhost, self.ip)
    flow2 = Switzerland.flow_mirror(flow1)
    #self.assertEqual(flow2, (ip,port2_s,localhost, port_s, prot_s))
    client1.send_message("active_flows", [[(0, "hash", flow1)], []])
    # This trick should get us two useable Alice IPs
    client2 = AliceLink(threading.Event(), None, self.net_config)
    client2.start()
    client2.ready.wait()
    client2.send_message("ping")
    client2.send_message("active_flows", [[(0, "hash", flow1)], []])
    
    mm1 = (flow1[0], flow1[2], "hash")
    mm2 = (flow2[0], flow2[2], "hash")
    time.sleep(3)
    self.server.global_flow_lock.acquire()
    try:
      print "Global flow table", self.server.flow_matchmaker
      # XXX fix these
      #self.assert_(self.server.global_flow_table.has_key(flow1))
      print "Hunting for", mm1, "\nand",  mm2
      self.assert_(self.server.flow_matchmaker.has_key(mm1))
      #self.assert_(not self.server.global_flow_table.has_key(flow2))
      self.assert_(not self.server.flow_matchmaker.has_key(mm2))

    finally:
      self.server.global_flow_lock.release()

    # Now tear things down
    client2.send_message("active_flows", [[], [0]])
    client1.send_message("active_flows", [[], [0]])

    time.sleep(2)
    self.server.global_flow_lock.acquire()
    try:
      print "Global flow table", self.server.flow_matchmaker
      #self.assertEqual(self.server.global_flow_table, {})
      self.assertEqual(self.server.flow_matchmaker, {})
    finally:
      self.server.global_flow_lock.release()

    nmf = lambda m : m[0] == "new-members"
    new_member_counts = [len(filter(nmf, c.in_log)) for c in [client1, client2]]
    print "nmc:", new_member_counts
    self.assert_(1 in new_member_counts)
    self.assert_(2 in new_member_counts)

  def random_reconciliator(self, link1, link2):
    from switzerland.server.Reconciliator import Reconciliator
    f = self.random_flow(self.localhost, self.ip)
    #a_to_b = SwitzerlandFlow(False,f[0],f[1],f[2],f[3],f[4], 0)
    #b_from_a = SwitzerlandFlow(True, f[0],f[1],f[2],f[3],f[4], 0)
    rec = Reconciliator(f, (f[0], f[2], "a" * Protocol.hash_length))
    dummy_id = 0
    rec.add_link(link1, dummy_id)
    rec.add_link(link2, dummy_id)
    return rec

  def testForgedReplies(self):
    print 80 * "-"
    print "  testForgedReplies"
    print 80 * "-"
    client1 = AliceLink(threading.Event(), None, self.lh_config)
    client1.handle_forged_in = client1.dummy_handle_forged_in
    client1.start()
    client1.ready.wait()
    client2 = AliceLink(threading.Event(), None, self.net_config)
    client2.handle_forged_in = client2.dummy_handle_forged_in
    client2.start()
    client2.ready.wait()
    server_thread1, server_thread2 = self.server.threads  # XXX not safe!!!
    # This interface is undocumented
    self.server.real_fi_handler = self.server.handle_fi_context
    self.server.handle_fi_context = self.server.hook_handle
    self.callback_count = 0
    contexts = {}
    for n in range(5):
      hash = Protocol.hash_length * chr(n)
      contexts[hash] = [repr(n)] * 3
    forgeries = contexts.keys()
    timestamps=[1,2,3,4,5]
    forgeries = zip(timestamps, forgeries)
    rec = self.random_reconciliator(server_thread1, server_thread2)
    frogs = (forgeries, rec)
    def callback(master, link, args, reply_seq_no):
      self.assertEqual(master, self.server)
      self.assertEqual(link, server_thread1)
      meta = args[0]
      data = args[1]
      replying_to = meta[0]
      remembered = meta[1]
      self.assertEqual(replying_to, "forged-in")
      self.assertEqual(remembered, frogs)
      self.callback_count += 1
      # okay, we've finished testing, now call the real method:
      master.real_fi_handler(link, args, reply_seq_no)
    self.server.hook_callback = callback
    client1.send_message("ping")

    server_thread1.send_message("forged-in", [0] + [forgeries], data_for_reply = frogs)
    time.sleep(1)
    client1.send_message("signoff")
    time.sleep(1)
    self.assertEqual(self.callback_count, 1)
   
   
def suite():
  return unittest.makeSuite(PacketBatchTestCase, 'test')

if __name__ == "__main__":
  unittest.main()


