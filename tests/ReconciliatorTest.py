import unittest
import sys

sys.path.append('..')

from switzerland.server import SwitzerlandFlow
from switzerland.client import Packet
from switzerland.server import Reconciliator
from switzerland.common import Protocol

class ReconciliatorTestCase(unittest.TestCase):
    def setUp(self):
        self.a_to_b = SwitzerlandFlow.SwitzerlandFlow(True, '\xc0\xa8\x00\x01', '\xff\xff', '\xc0\xa8\x00\x02', '\x2a', '\x06', 0)
        self.b_from_a = SwitzerlandFlow.SwitzerlandFlow(True, '\xc0\xa8\x00\x01', '\xff\xff', '\xc0\xa8\x00\x02', '\x2a', '\x06', 0)
        self.r = Reconciliator.Reconciliator(self.a_to_b, self.b_from_a)

    def tearDown(self):
        self.r = None
        self.b_from_a = None
        self.a_to_b = None

    def testSimpleOK(self):
        hash0 = '0' * Protocol.hash_length
        self.a_to_b.new_batch(2, hash0)
        forged = self.r.sent_by_alice()
        assert len(forged) == 0, 'not expecting forges'
        assert self.r.newest_information_from_a == 2, 'newest_from_a should be 2 now'
        assert self.r.sent_packets.has_key(hash0), 'expecting 0 flagged sent'
        self.b_from_a.new_batch(2, hash0)
        forged = self.r.recd_by_bob()
        assert len(forged) == 0, 'not expecting forges'
        assert not self.r.recd_packets.has_key(hash0), 'expecting 0 not flagged recd'
        assert not self.r.sent_packets.has_key(hash0), 'expecting 0 not flagged sent'
        assert len(self.r.a_to_b.batches) == 0, 'expecting a_to_b empty'
        assert len(self.r.b_from_a.batches) == 0, 'expecting b_from_a empty'

    def testSimpleDrop(self):
        hash0 = '0' * Protocol.hash_length
        self.a_to_b.new_batch(2, hash0)
        forged = self.r.sent_by_alice()
        assert len(forged) == 0, 'not expecting forges'
        assert self.r.newest_information_from_a == 2, 'newest_from_a should be 2 now'
        assert self.r.sent_packets.has_key(hash0), 'expecting 0 flagged sent'
        dropped = self.r.bob_sent_flow_status(3+Reconciliator.Reconciliator.drop_timeout)
        assert len(dropped) == 1, 'expecting 1 drop'
        assert dropped[0] == hash0, 'expecting hash 0 dropped'
        assert len(self.r.b_from_a.batches) == 0, 'expecting batch queue cleared'
        assert len(self.r.a_to_b.batches) == 0, 'expecting batch queue cleared'

    def testSimpleForge(self):
        hash0 = '0' * Protocol.hash_length
        self.b_from_a.new_batch(2, hash0)
        forged = self.r.recd_by_bob()
        assert len(forged) == 0, 'not expecting forges'
        assert self.r.newest_information_from_b == 2, 'newest_from_b should be 2 now'
        forged = self.r.alice_sent_flow_status(3)
        assert len(forged) == 1, 'expecting forgery'
        assert forged[0] == hash0, 'expecting hash 0 forged'
        assert len(self.r.b_from_a.batches) == 0, 'expecting batch queue empty'
        assert len(self.r.a_to_b.batches) == 0, 'expecting batch queue empty'
    
    def testRandom(self):
        hashes = [ Protocol.hash_length * str(i) for i in range(9) ] 
        pass
    
def suite():
    return unittest.makeSuite(ReconciliatorTestCase, 'test')

if __name__ == "__main__":
    unittest.main()

