from switzerland.client import Packet
from switzerland.common import Protocol

#batch_size = 10 # packets per batch
batch_size = int(1000 / Protocol.hash_length)
timeout = 10                   # seconds before sending partially full batch

class PacketBatch:
    """A batch of packets."""

    def __init__(self):
        self.packets = []
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
        """Add new packet to batch.

        The packet must be more recent than any in the batch.
        """

        assert isinstance(packet, Packet.Packet), 'expecting packet'
        assert not self.full, 'adding packet to full batch'
        assert self.newest_timestamp == None or \
            packet.timestamp >= self.newest_timestamp, \
            'adding older packet to batch'

        # Add packet to queue.
        self.packets.append(packet)

        # Update oldest and newest timestamps.
        if self.oldest_timestamp == None:
            self.oldest_timestamp = packet.timestamp
        self.newest_timestamp = packet.timestamp

        # Update size.
        self.size += 1
        if self.size == batch_size:
            self.full = True

    def find_hash(self, hash):
        """Return -1 if hash not present, position otherwise."""

        for i in xrange(len(self)):
            if self.packets[i].get_hash()[:-2] == hash:
                return i
        return -1

    def contains_hash(self, hash):
        """Does batch contain a packet with the given hash?"""

        for p in self:packets:
            if p.get_hash()[:-2] == hash:
                return True

        return False
        #return any(p.get_hash()[:-2] == hash for p in self.packets)

    def get_hashes(self):
        """Return a string of hashes for packets contained in the batch."""

        return ''.join(map(lambda x: x.get_hash(), self.packets))

