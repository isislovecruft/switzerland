import unittest
import sys
import array
import binascii

sys.path.append('..')
from switzerland.client import Packet

class PacketTestCase(unittest.TestCase):
    def setUp(self):
        #                   MAC header   |l           p     ssssddddssdd
        self.tpkt        = "01234567890123\x0545678901\x0678abcdefghijkl01234567890123456789"
        self.upkt        = "01234567890123\x0545678901\x1178abcdefghijkl01234567890123456789"
        #                   l                 p           ssssddddssdd
        self.zeroed_data = "\x05\x00567890\x00\x06\x00\x00abcdefghijkl012345678901\x00\x00456789"

    def tearDown(self):
        pass

    def testInitNoHash(self):
        """ test initializing without passing in a hash """
        packet = Packet.Packet(12345, self.tpkt)
        assert packet.timestamp == 12345, 'bad timestamp'
        assert packet.hash == None, 'hash should be None by default'
        assert packet.data[1] == '\x00', 'tos not zeroed'
        assert packet.data[8] == '\x00', 'tos not zeroed'
        assert packet.data[10] == '\x00', 'ip checksum not zeroed'
        assert packet.data[11] == '\x00', 'ip checksum not zeroed'
        assert packet.data == self.zeroed_data, 'data incorrect'
        assert packet.size == len(self.tpkt)-Packet.MAC_header_length, 'bad size'
        assert packet.proto == '\x06', 'bad proto'
        assert packet.source_ip == 'abcd', 'bad source ip'
        assert packet.source_port == 'ij', 'bad source port'
        assert packet.dest_ip == 'efgh', 'bad dest ip'
        assert packet.dest_port == 'kl', 'bad dest port'
        assert packet._flow_id == 'abcdijefghkl\x06', 'bad flow id'
        assert packet.flow_id() == packet._flow_id, 'accessor bad'

    def testInitHash(self):
        """ test initializing with a hash """
        good_hash = "01234567890123456789"
        packet = Packet.Packet(54321, self.tpkt, good_hash)
        assert packet.timestamp == 54321, 'bad timestamp'
        assert packet.hash == good_hash, 'hash should be None by default'
        assert packet.data[1] == '\x00', 'tos not zeroed'
        assert packet.data[8] == '\x00', 'tos not zeroed'
        assert packet.data[10] == '\x00', 'checksum not zeroed'
        assert packet.data[11] == '\x00', 'checksum not zeroed'
        assert packet.data == self.zeroed_data, 'data incorrect'
        hash = packet.get_hash()
        assert hash == good_hash, 'hash got modified'
        assert packet.size == len(self.tpkt)-Packet.MAC_header_length, 'bad size'
        assert packet.proto == '\x06', 'bad proto'
        assert packet.source_ip == 'abcd', 'bad source ip'
        assert packet.source_port == 'ij', 'bad source port'
        assert packet.dest_ip == 'efgh', 'bad dest ip'
        assert packet.dest_port == 'kl', 'bad dest port'
        assert packet._flow_id == 'abcdijefghkl\x06', 'bad flow id'
        assert packet.flow_id() == packet._flow_id, 'accessor bad'

    def testFlowInfoTCP(self):
        """ test extracting the flow info from ip/tcp/udp headers """
        packet = Packet.Packet(23956356, self.tpkt)
        assert packet.proto == '\x06', 'bad proto'
        assert packet.source_ip == 'abcd', 'bad source ip'
        assert packet.source_port == 'ij', 'bad source port'
        assert packet.dest_ip == 'efgh', 'bad dest ip'
        assert packet.dest_port == 'kl', 'bad dest port'
        assert packet._flow_id == 'abcdijefghkl\x06', 'bad flow id'
        assert packet.flow_id() == packet._flow_id, 'accessor bad'

    def testFlowInfoUDP(self):
        packet = Packet.Packet(3614242, self.upkt)
        assert packet.proto == '\x11', 'bad proto'
        assert packet.source_ip == 'abcd', 'bad source ip'
        assert packet.source_port == 'ij', 'bad source port'
        assert packet.dest_ip == 'efgh', 'bad dest ip'
        assert packet.dest_port == 'kl', 'bad dest port'
        assert packet._flow_id == 'abcdijefghkl\x11', 'bad flow id'
        assert packet.flow_id() == packet._flow_id, 'accessor bad'

    def testHash(self):
        """ test hash algorithm """
        packet = Packet.Packet(12345, self.tpkt)
        good_hash = '\xc9\xf7\x00\x24\x07\xf1\x1c\x95\xda\xf6\x3e\x74\x54\xe4\xe7\x62\x77\xad\x31\x52'
        hash = packet.get_hash()
        #print ''.join([ "\\x%x" % (ord(i)) for i in hash ])
        assert hash == good_hash, 'bad sha-1 hash'
        assert packet.hash == good_hash, 'expecting hash to be cached'

    def testNormalize(self):
        data1 = '00000000000000E\x00\x01P\xf5\xa8@\x00\x00\x06\x00\x00E\x0c\x87\xa5\x18\x15&:\xcc\x8b*\xbd\xea%#qkv{?P\x18\x00\xb7\x0cC\x00\x00GET /announce?info_hash=hd%88%05%AC%A0%22%C6%C62Iy%19%8C%F77%D5%3D%ED7&peer_id=M3-4-2--ffb01e7ef976&port=6881&key=5d6cb5a9&uploaded=0&downloaded=0&left=111081290&compact=1&event=started HTTP/1.1\r\nHost: 24.21.38.58:10941\r\nUser-Agent: Python-urllib/2.5\r\nConnection: close\r\nAccept-Encoding: gzip\r\n\r\n'
	data2 = '00000000000000E\x00\x01P\xf5\xa8@\x00\x00\x06\x00\x00E\x0c\x87\xa5\x18\x15&:\xcc\x8b*\xbd\xea%#qkv{?P\x18\x00\xb7H\x84\x00\x00GET /announce?info_hash=hd%88%05%AC%A0%22%C6%C62Iy%19%8C%F77%D5%3D%ED7&peer_id=M3-4-2--ffb01e7ef976&port=6881&key=5d6cb5a9&uploaded=0&downloaded=0&left=111081290&compact=1&event=started HTTP/1.1\r\nHost: 24.21.38.58:10941\r\nUser-Agent: Python-urllib/2.5\r\nConnection: close\r\nAccept-Encoding: gzip\r\n\r\n'
	packet1 = Packet.Packet(12345, data1)
	packet2 = Packet.Packet(12345, data2)
	hash1, hash2 = packet1.get_hash(), packet2.get_hash()
	assert hash1 == hash2, "tcp checksum not ignored"

        data1 = '00000000000000E\x00\x00(\x04C\x00\x00\x00\x06\x00\x00\x18\x15&:E\x0c\x87\xa51$\x90\xf5\x00\x00\x00\x00\xd0mm\xecP\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        data2 = '00000000000000E\x00\x00(\x04C\x00\x00\x00\x06\x00\x00\x18\x15&:E\x0c\x87\xa51$\x90\xf5\x00\x00\x00\x00\xd0mm\xecP\x14\x00\x00\x00\x00\x00\x00'
        packet1 = Packet.Packet(12345, data1)
        packet2 = Packet.Packet(12345, data2)
        hash1, hash2 = packet1.get_hash(), packet2.get_hash()
        assert hash1 == hash2, "ethernet trailer not ignored"

def suite():
    return unittest.makeSuite(PacketTestCase, 'test')

if __name__ == "__main__":
    unittest.main()
