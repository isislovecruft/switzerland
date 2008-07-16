import Packet
import PacketQueue
from Flow import Flow
import types
import struct
import socket as s
from LinkedList import LinkedList

class Batch:
  def __init__(self, timestamp, hash_list):
    self.timestamp = timestamp
    self.hash_list = hash_list

import Protocol
class SwitzerlandFlow(Flow):
  """ SwitzerlandFlow keeps around a lightweight list of hashes per batch. """

  def __init__(self, inbound, src_ip, src_port, dest_ip, dest_port, proto, now):
    Flow.__init__(self, inbound, src_ip, src_port, dest_ip, dest_port, proto, now)
    self.batches = LinkedList()
    self.hash_length = Protocol.hash_length

  def new_batch(self, timestamp, hashes):
    pos = 0
    list = LinkedList()
    for n in range(Protocol.hashes_in_batch(hashes)):
      list.append(hashes[pos:pos+self.hash_length])
      pos += self.hash_length

    self.batches.append(Batch(timestamp, list))

