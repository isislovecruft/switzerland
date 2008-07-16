import unittest
import sys

sys.path.append('..')
from switzerland.client import Packet
from switzerland.client import PacketBatch
from switzerland.client import PacketQueue

class PacketQueueTestCase(unittest.TestCase):
    def setUp(self):
        self.packets = []
        for i in range(0,1+PacketBatch.batch_size):
            data = ''.join([ `i` for j in range(1,41) ])
            self.packets.append(Packet.Packet(i, data))

    def tearDown(self):
        self.packets = []

    def testInit(self):
        queue = PacketQueue.PacketQueue()
        assert queue._length == 0, 'queue is empty'
        assert queue._first_unsent == 0, 'unsent packet should be 0'

    def testAppend(self):
        queue = PacketQueue.PacketQueue()
        queue.append(self.packets[0])
        assert queue._length == 1, 'expecting one entry'
        assert queue._first_unsent == 0, 'expecting unsent at 0'
        assert queue.has_batches_to_send(), 'should have packets'
        assert queue.next_batch_to_send().packets[0] == self.packets[0], \
            'should be at front'

    def testAppendMany(self):
        queue = PacketQueue.PacketQueue()
        for i in range(0,PacketBatch.batch_size):
            queue.append(self.packets[i])
            assert queue._length == 1, 'one batch'
            assert queue._first_unsent == 0, 'first to send is 0'
            assert queue.has_batches_to_send(), 'should have packets'
            assert queue.next_batch_to_send().packets[i] == self.packets[i], \
                'should be at front'
        queue.append(self.packets[-1])
        assert queue._length == 2, 'should be two batches now'
        assert queue._queue[0].packets[0] != self.packets[-1],\
            'should not have been added to first batch'
        assert queue._queue[1].packets[0] == self.packets[-1],\
            'should have been added to second batch'
        assert queue.has_batches_to_send(), 'should have packets'

    def testClean(self):
        queue = PacketQueue.PacketQueue()
        queue.clean(1) # should work on empty queue
        for i in range(0,PacketBatch.batch_size):
            self.packets[i].timestamp = 1
            queue.append(self.packets[i])
            assert queue._length == 1, 'should be one batch now'
            queue.clean(1)
            assert queue._length == 1, 'should still be one batch now'
        self.packets[-1].timestamp = 1+PacketQueue.time_to_keep_packets
        queue.append(self.packets[-1])
        assert queue._length == 2, 'should be two batches now'
        queue.clean(1+PacketQueue.time_to_keep_packets)
        assert queue._length == 2, 'should still be two batches'
        newer_batch = queue._queue[1]
        queue.clean(2+PacketQueue.time_to_keep_packets)
        assert queue._length == 1, 'should have cleaned old batch'
        assert queue._queue[0] == newer_batch, 'newer batch should remain'
        for i in range(0,PacketBatch.batch_size):
            self.packets[i].timestamp = 1+PacketQueue.time_to_keep_packets
            queue.append(self.packets[i])
        assert queue._length == 2, 'should have two batches now'
        queue.clean(1+2*PacketQueue.time_to_keep_packets)
        assert queue._length == 2, 'should still have two batches'
        queue.clean(2+2*PacketQueue.time_to_keep_packets)
        assert queue._length == 0, 'should have no batches now'
        
def suite():
    return unittest.makeSuite(PacketQueueTestCase, 'test')

if __name__ == "__main__":
    unittest.main()
