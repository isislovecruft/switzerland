from switzerland.client import Packet
from switzerland.common import Protocol

#batch_size = 10 # packets per batch
batch_size = int(1000 / Protocol.hash_length)
timeout = 10 # seconds before sending partially full batch

class PacketBatch:
    """ a batch of packets """

    def __init__(self):
        self.packets = [ ]
        self.size = 0
        self.full = False
        self.sent = False
        self.oldest_timestamp = None 
        self.newest_timestamp = None

    def __len__(self):
        return self.size

    def __getitem__(self, n):
        return self.packets[n]
    
    def add(self, packet):
        """ add new packet to batch
            (packet must be more recent than any in batch) """
        assert isinstance(packet, Packet.Packet), 'expecting packet'
        assert not self.full, 'adding packet to full batch'
        assert self.newest_timestamp == None or \
            packet.timestamp >= self.newest_timestamp, \
            'adding older packet to batch'

        # add packet to queue
        self.packets.append(packet)

        # update oldest and newest timestamps
        if self.oldest_timestamp == None:
            self.oldest_timestamp = packet.timestamp
        self.newest_timestamp = packet.timestamp

        # update size
        self.size += 1
        if self.size == batch_size:
            self.full = True

    def find_hash(self, hash):
        """ return -1 if hash not present, position otherwise """
        for i in xrange(len(self)):
            if self.packets[i].get_hash()[:-2] == hash:
                return i
        return -1

    def contains_hash(self, hash):
        """ does batch contain a packet with the given hash? """
        for p in self.packets:
            if p.get_hash()[:-2] == hash:
                return True
        return False

    def get_hashes(self):
        """ return a string of hashes for packets contained in the batch """
        return ''.join(map(lambda x: x.get_hash(), self.packets))

