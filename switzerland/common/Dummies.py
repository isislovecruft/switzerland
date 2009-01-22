#!/usr/bin/env python

# These are useful in some test cases and other unexpected contexts where we
# don't want to have to instantiate the real things.  What they end up having
# to implement is probably quite informative.

import sys
import threading

from switzerland.client import AliceConfig

class DummyFlowManager:
  def __init__(self):
      self.queue = []
      self.ip_ids = {}
  def handle_packet(self, packet):
      self.queue.append(packet)

class DummyAlice:
  config = AliceConfig.AliceConfig(interface="lo")
  quit_event = threading.Event()
  if len(sys.argv) > 1:
    config.interface = sys.argv[1]
  else:
    config.interface = "ath0"
  fm = DummyFlowManager()
