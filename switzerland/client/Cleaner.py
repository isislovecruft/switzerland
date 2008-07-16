import threading, thread
import time

class Cleaner(threading.Thread):
    """ periodically clean up stale packets and expired flows """
    interval = 10 # seconds between waking up and cleaning

    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.parent = parent

    def run(self):
      try:
        while True:
            time.sleep(Cleaner.interval)
            self.parent.fm.clean(int(time.time()))
      except:
        if self.parent.quit_event.set != None:    # exit-time crash avoidance
          self.parent.quit_event.set()

