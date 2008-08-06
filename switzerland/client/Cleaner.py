import threading
import time

class Cleaner(threading.Thread):
    """Periodically clean up stale packets and expired flows."""

    interval = 10              # seconds between waking up and cleaning

    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.parent = parent

    def run(self):
        try:
            while True:
                time.sleep(Cleaner.interval)
                self.parent.fm.clean(int(time.time()))
        except:
            # Exit-time crash avoidance.
            if self.parent.quit_event.set != None:
                self.parent.quit_event.set()

