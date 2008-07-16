import unittest
import PacketTest
import PacketBatchTest
import PacketQueueTest
import FlowManagerTest
import PacketListenerTest

suite = unittest.TestSuite()
suite.addTest(PacketTest.suite())
suite.addTest(PacketBatchTest.suite())
suite.addTest(PacketQueueTest.suite())
suite.addTest(FlowManagerTest.suite())
suite.addTest(PacketListenerTest.suite())
runner = unittest.TextTestRunner()
runner.run(suite)
