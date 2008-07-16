#!/usr/bin/env python2.5

import sys
sys.path.append('../src/common')
from switzerland.client import Packet
from binascii import hexlify

# HashDump.py dumpfile private_ip public_ip [firewalled peer_firewalled]

class FakeConfig:
    def __init__(self):
        self.private_ip = sys.argv[2]
class FakeLink:
    def __init__(self):
        self.firewalled = "firewalled" in sys.argv[3:]
        self.public_ip = sys.argv[3]
class FakeAlice:
    def __init__(self):
        self.config = FakeConfig()
        self.link = FakeLink()
        self.fm=FakeFM()
class FakeFM():
    def __init__(self):
        self.ipids = {}

raw_packet = file(sys.argv[1], "r")
data = raw_packet.read()
raw_packet.close()

p = Packet.Packet(0, data, FakeAlice())
print "IPID is", hexlify(p.ipid)
p.peer_firewalled = "peer_firewalled" in sys.argv[3:]
hash = p.get_hash()
print "hash: ", hexlify(hash)
