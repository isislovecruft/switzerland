import unittest
import sys
import array

sys.path.append('..')
from switzerland.client import FlowManager
from switzerland.client import Packet
from switzerland.client import PacketQueue
from switzerland.client import PacketBatch
from switzerland.client import AliceFlow
from switzerland.client import Flow

class FlowManagerTestCase(unittest.TestCase):
    def setUp(self):
        self.data = "0123456789012345678901234567890123456789"
        self.data2 = "abcdefghijklmnopqrstuvwxyz"
        self.packet = Packet.Packet(12345, self.data)
        self.packet2 = Packet.Packet(12346, self.data2)
        self.flow_manager = FlowManager.FlowManager('my-ip', False)

    def tearDown(self):
        self.flow_manager = None

    def testInitFlow(self):
        flow = AliceFlow.AliceFlow(True, 'aaaa', 'bb', 'cccc', 'dd', 'e', 12345)
        assert flow.src_ip == 'aaaa', 'bad source ip'
        assert flow.src_port == 'bb', 'bad source port'
        assert flow.dest_ip == 'cccc', 'bad dest ip'
        assert flow.dest_port == 'dd', 'bad dest port'
        assert flow.proto == 'e', 'bad proto'
        assert flow.queue != None, 'expecting queue'
        assert flow.time_last_active == 12345, 'bad time last active'
        assert flow.time_started == 12345, 'bad time started'
        assert flow.bytes_transferred == 0, 'expecting no bytes'
        assert flow.packets_transferred == 0, 'expecting no packets'

    def testAddFlow(self):
        assert len(self.flow_manager.flows) == 0, 'should not have any flows'
        self.flow_manager.handle_packet(self.packet)
        assert len(self.flow_manager.flows) == 1, 'should now have a flow'
        assert self.flow_manager.flows.has_key(self.packet.flow_id()), 'flow id should match'
        fm_flow = self.flow_manager.flows[self.packet.flow_id()]
        assert fm_flow.bytes_transferred == self.packet.size, 'should have sent bytes from packet'
        assert fm_flow.packets_transferred == 1, 'should have transferred one packet'

    def testAppendToFlow(self):
        assert len(self.flow_manager.flows) == 0, 'should not have any flows'
        self.flow_manager.handle_packet(self.packet)
        assert len(self.flow_manager.flows) == 1, 'should now have a flow'
        self.flow_manager.handle_packet(self.packet)
        assert len(self.flow_manager.flows) == 1, 'should only have one flow'
        assert self.flow_manager.flows.has_key(self.packet.flow_id()), 'flow id should match'
        fm_flow = self.flow_manager.flows[self.packet.flow_id()]
        assert fm_flow.bytes_transferred == 2*self.packet.size, 'should have sent bytes from packet x2'
        assert fm_flow.packets_transferred == 2, 'should have transferred two packets'

    def testMultipleFlows(self):
        assert len(self.flow_manager.flows) == 0, 'should not have any flows'
        self.flow_manager.handle_packet(self.packet)
        assert len(self.flow_manager.flows) == 1, 'should now have a flow'
        self.flow_manager.handle_packet(self.packet)
        assert len(self.flow_manager.flows) == 1, 'should only have one flow'
        self.flow_manager.handle_packet(self.packet2)
        assert len(self.flow_manager.flows) == 2, 'should have two flows'
        assert self.flow_manager.flows.has_key(self.packet.flow_id()), 'should have flow'
        assert self.flow_manager.flows.has_key(self.packet2.flow_id()), 'should have flow'
        fm_flow = self.flow_manager.flows[self.packet.flow_id()]
        assert fm_flow.bytes_transferred == 2*self.packet.size, 'should have sent bytes from packet'
        assert fm_flow.packets_transferred == 2, 'should have transferred one packet'
        fm_flow = self.flow_manager.flows[self.packet2.flow_id()]
        assert fm_flow.bytes_transferred == self.packet2.size, 'should have sent bytes from packet'
        assert fm_flow.packets_transferred == 1, 'should have transferred one packet'

    def testClean(self):
        # test removing a stale flow
        self.flow_manager.handle_packet(self.packet)
        self.flow_manager.handle_packet(self.packet2)
        assert len(self.flow_manager.flows) == 2, 'should have two flows'
        assert self.flow_manager.flows.has_key(self.packet.flow_id())
        fm_flow = self.flow_manager.flows[self.packet.flow_id()]
        fm_flow.time_last_active = 0
        assert self.flow_manager.flows.has_key(self.packet2.flow_id())
        fm_flow = self.flow_manager.flows[self.packet2.flow_id()]
        fm_flow.time_last_active = Flow.Flow.timeout-1
        self.flow_manager.clean(1+Flow.Flow.timeout)
        assert len(self.flow_manager.flows) == 1, 'should have one flow'
        assert not self.flow_manager.flows.has_key(self.packet.flow_id()), 'should have removed flow'
        assert self.flow_manager.flows.has_key(self.packet2.flow_id()), 'should still have other flow'

        # test removing stale packets from a flow
        packet3 = Packet.Packet(0, self.data)
        packet4 = Packet.Packet(Flow.Flow.timeout, self.data)
        for i in range(0,PacketBatch.batch_size):
            self.flow_manager.handle_packet(packet3)
        self.flow_manager.handle_packet(packet4)
        assert self.flow_manager.flows.has_key(packet3.flow_id()), 'should have flow'
        fm_flow = self.flow_manager.flows[packet3.flow_id()]
        assert fm_flow.queue._length == 2, 'should have two batches'
        self.flow_manager.clean(PacketQueue.time_to_keep_packets)
        assert self.flow_manager.flows.has_key(packet3.flow_id()), 'should have flow'
        assert fm_flow.queue._length == 2, 'should have two batches still'
        self.flow_manager.clean(1+PacketQueue.time_to_keep_packets)
        assert self.flow_manager.flows.has_key(packet3.flow_id()), 'should have flow'
        assert fm_flow.queue._length == 1, 'should have one batch now'
        assert fm_flow.queue._queue[0].size == 1, 'should have one packet in batch'
        assert fm_flow.queue._queue[0].packets[0] == packet4, 'packet4 should remain'

    def testHandlePacketReturn(self):
        for j in range(0,3):
            for i in range(0,PacketBatch.batch_size-1):
                full = self.flow_manager.handle_packet(self.packet)
                assert not full, 'not expecting to have formed full batch'
            full = self.flow_manager.handle_packet(self.packet)
            assert full, 'expecting full batch'

    def testStr(self):
        flow = Flow.Flow(True, '\x01\x02\x03\x04', '\x05\x06', '\x07\x08\x09\x0a', '\x0b\x0c', '\x06', 12345)
        assert str(flow) == '1.2.3.4:1286 -> 7.8.9.10:2828 (tcp)'

def suite():
    return unittest.makeSuite(FlowManagerTestCase, 'test')

if __name__ == "__main__":
    unittest.main()

