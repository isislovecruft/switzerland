#!/usr/bin/env python
import unittest
import logging
from switzerland.common import PacketDiff

class PacketDiffTestCase(unittest.TestCase):
    def setUp(self):
      pass

    def testRSTDetection(self):
        logging.basicConfig()
        file1 = open("packets/random_ssh_packet")
        file2 = open("packets/random_ssh_packet_rst")
        from switzerland.common.Dummies import DummyAlice
        p = PacketDiff.PacketDiffer(file1.read(), file2.read(), DummyAlice())
        result = p.diff()
        self.assertEquals(len(result.strip().split("\n")), 1)
        self.assert_("TCP RST" in result)

def suite():
  return unittest.makeSuite(PacketDiffTestCase, 'test')

if __name__ == "__main__":
  unittest.main()

