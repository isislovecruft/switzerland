from switzerland.client import Packet
from switzerland.client import PacketBatch

time_to_keep_packets = 120     # seconds before discarding packets

class PacketQueue:
    """Queue of PacketBatches."""

    def __init__(self):
        # Batches in oldest to youngest order in queues.
        self.unsent_batches = []
        self.sent_batches = []

    def __len__(self):
        """Total number of batches tracked."""

        return len(self.sent_batches) + len(self.unsent_batches)

    def __getitem__(self, i):
        """Get a sent or unsent batch."""

        sent_batch_length = len(self.sent_batches)
        if i < sent_batch_length:
            return self.sent_batches[i]
        else:
            return self.unsent_batches[i - sent_batch_length]

    def has_unsent_batches(self):
        """Are there unsent batches?"""

        return bool(self.unsent_batches)

    def get_oldest_unsent_batch(self):
        """Get next (oldest) unsent batch."""

        return self.unsent_batches[0]

    def mark_oldest_batch_sent(self):
        """Mark oldest batch sent."""

        self.sent_batches.append(self.unsent_batches.pop(0))

    def clean(self, now):
        """Clean out stale batches in sent and unsent queues

        @param  now  current time in seconds since epoch
        """

        self.__clean_queue(self.sent_batches, now)
        self.__clean_queue(self.unsent_batches, now)

    def __clean_queue(self, queue, now):
        """Clean out stale batches.

        @param  now  current time in seconds since epoch
        """

        while queue:
            last_update = queue[0].newest_timestamp
            if last_update != None and \
               now - last_update > time_to_keep_packets:
                queue.pop(0)
            else:
                break

    def append(self, packet):
        """Add incoming packet to current working batch.  Return true if the
        batch is full."""

        assert isinstance(packet, Packet.Packet), 'expecting Packet'

        if not self.unsent_batches or self.unsent_batches[-1].full:
            self.unsent_batches.append(PacketBatch.PacketBatch())
        self.unsent_batches[-1].add(packet)

        return self.unsent_batches[-1].full

