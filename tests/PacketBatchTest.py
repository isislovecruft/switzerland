import unittest
import sys

sys.path.append('../src/common')
from switzerland.client import PacketBatch
from switzerland.client import Packet

class PacketBatchTestCase(unittest.TestCase):
    def setUp(self):
        self.packets = []
        for i in range(0,PacketBatch.batch_size):
            data = ''.join([ `i` for j in range(1,41) ])
            self.packets.append(Packet.Packet(i, data))

    def tearDown(self):
        self.packets = []

    def testAdd(self):
        batch = PacketBatch.PacketBatch()
        assert batch.size == 0, 'expecting batch to be empty'
        assert not batch.full, 'batch full'
        assert not batch.sent, 'batch not sent'
        batch.add(self.packets[0])
        assert batch.size == 1, 'expecting 1 packet in batch'
        if PacketBatch.batch_size == 1:
            assert batch.full, 'expecting batch to be full'
        else:
            assert not batch.full, 'not expecting batch full'
        assert batch.oldest_timestamp == self.packets[0].timestamp, \
            'expecting added packet to be oldest'
        assert batch.newest_timestamp == self.packets[0].timestamp, \
            'expecting added packet to be newest'

    def testFull(self):
        batch = PacketBatch.PacketBatch()
        for i in range(0,PacketBatch.batch_size):
            batch.add(self.packets[i])
            assert batch.size == i+1, 'size wrong'
            assert i == PacketBatch.batch_size-1 or not batch.full, 'should not be full'
            assert batch.newest_timestamp == self.packets[i].timestamp, \
                'most recently added packet not newest timestamp'
            assert batch.oldest_timestamp == self.packets[0].timestamp, \
                'oldest timestamp changed'
        assert batch.full, 'batch should be full'
        
def suite():
    return unittest.makeSuite(PacketBatchTestCase, 'test')

if __name__ == "__main__":
    unittest.main()
