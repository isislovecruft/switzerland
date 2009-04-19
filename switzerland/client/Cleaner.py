import threading
import time
import traceback
import logging

log = logging.getLogger('alice.cleaner')
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
                log.info("Cleaner exception:\n" + traceback.format_exc())
                self.parent.quit_event.set()

