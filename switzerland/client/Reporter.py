import threading, thread
import time
import logging
import traceback
from switzerland.client import PacketBatch

log = logging.getLogger('alice.reporter')

class Reporter(threading.Thread):
    """ send packet batches and report flow activity """
    flow_activity_interval = 10 # seconds between sending flow updates
    batch_wait_timeout = 1 # maximum time to wait for a full batch

    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.parent = parent
        self.link = parent.link
        self.flow_manager = parent.fm
        self.batch_to_process = parent.fm.batch_to_process 
        self.last_flow_activity_update = None
        if self.parent.config.debug_monotonicity:
            self.latest = 0

    def send_flow_stats(self):
        """ send stats about flows """
        pass

    def send_flow_announcements(self):
        """ send information about which flows have been opened/closed """
        if len(self.flow_manager.new_flows) == 0 and \
           len(self.flow_manager.deleted_flows) == 0:
           return # don't bother reporting flow activity if nothing new to report
        new     = [f.summary() for f in self.flow_manager.new_flows]
        deleted = [f.id        for f in self.flow_manager.deleted_flows]

        self.link.send_message("active_flows", [new, deleted])

        for flow in self.flow_manager.new_flows:
            flow.reported = True
        self.flow_manager.new_flows = [ ]
        self.flow_manager.deleted_flows = [ ]

    def send_flow_activity(self):
        self.send_flow_announcements()
        self.send_flow_stats()

    def send_batch(self, batch, flow, now):
        """ send packet batch """
        # have to report flow before sending batches from it
        if not flow.reported: 
            # XXX this opening_hash juggling could be cleaned up...
            self.send_flow_announcements()
        hashes = batch.get_hashes()
        timestamp = batch.newest_timestamp
        if self.parent.config.debug_monotonicity:
            if timestamp > self.latest:
                self.latest = timestamp
            else:
                log.debug("send-batch out of order by %gs" % (self.latest - timestamp))
        if flow.inbound:
            self.link.send_message("recd", [flow.id, timestamp, hashes])
        else:
            self.link.send_message("sent", [flow.id, timestamp, hashes])
	#for p in batch.packets:
	#    log.debug("%s %s", p.hash, p.data)
        #log.debug("%d [%d,%d] %d packets for %s", \
        #    now, batch.oldest_timestamp, batch.newest_timestamp, batch.size, flow)

    def run(self):
      try:
        while True:
            self.batch_to_process.acquire()
            # wait for a full batch
            self.batch_to_process.wait(Reporter.batch_wait_timeout) 
            # now either there's a full batch or we timed out waiting

            # This looks crazy, but it prevents lots of exceptions during
            # multi-threaded shutdown (the previous line is a long wait)
            try:
              now = int(time.time())
            except:
              return

            # scan batches
            for flow in self.flow_manager.flows.values():
                while flow.queue.has_unsent_batches():
                    batch = flow.queue.get_oldest_unsent_batch()
                    time_batch_open = now - batch.oldest_timestamp
                    # if batch completed or timed out, send it and look at the next
                    if batch.full or time_batch_open > PacketBatch.timeout:
                        self.send_batch(batch, flow, now)
                        flow.queue.mark_oldest_batch_sent()
                        batch.sent = True
                        batch.full = True
                    # otherwise nothing more to do for this flow
                    else:
                        break

            # send flow updates
            if self.last_flow_activity_update == None or \
               now - self.last_flow_activity_update > Reporter.flow_activity_interval:
                self.send_flow_activity()
                self.last_flow_activity_update = now

            self.batch_to_process.release()
      except:
        if traceback:    # only false during interpreter shutdown
          traceback.print_exc()
          self.parent.quit_event.set()
        return

