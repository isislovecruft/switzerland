import unittest
import sys

sys.path.append('..')
import threading
from switzerland.client import PacketBatch
from switzerland.client import import PacketQueue
from switzerland.client import import PacketListener

class DummyFlowManager:
    def __init__(self):
        self.queue = []
    def handle_packet(self, packet):    
        self.queue.append(packet)

class PacketListenerTestCase(unittest.TestCase):
    def setUp(self):
        self.flow_manager = DummyFlowManager()
    def tearDown(self):
        self.flow_manager = None
    def testInit(self):
        listener = PacketListener.PacketListener(self.flow_manager, threading.Condition())
        assert listener._flow_manager == self.flow_manager, 'flow manager should point to ours'
        assert listener._live == None, 'live should not be set'
        assert listener._reader == None, 'no reader should exist'
    def testOffline(self):
        listener = PacketListener.PacketListener(self.flow_manager, threading.Condition())
        listener.open_offline('test1.pcap')
        assert listener._live == False, 'not live'
        assert listener._reader != None, 'expecting reader'
        listener.collect()
        queue = self.flow_manager.queue
        assert len(queue) == 1, 'expecting packet'
        good_data = '\x00\x1d~d\r7\x00\x1c\xb3s\xe4\x84\x08\x00E\x00\x004\xc6\x17@\x00\x00\x06\x00\x00\xc0\xa8\x01eJ}\x13S\xcb\xa0\x00PI\xfbLz\x1a\x87\x88\xeb\x80\x11\xff\xff]\x87\x00\x00\x01\x01\x08\n\x02\xcf\xf7\xc3\x1c\xaa\xdcA'
        first_timestamp = 1204515961
        packet = queue[0]
        assert packet.data == good_data, 'bad packet data'
        assert packet.timestamp == first_timestamp, 'bad timestamp'
        # loop until queue stops growing
        last_size = 0; num_packets = 1
        while last_size != len(queue):
            last_size = len(queue)
            listener.collect()
            num_packets += 1
        assert num_packets == 56, 'expecting 56 total packets'
        
def suite():
    return unittest.makeSuite(PacketListenerTestCase, 'test')

if __name__ == "__main__":
    unittest.main()

