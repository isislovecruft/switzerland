#!/usr/bin/env python

from subprocess import Popen, PIPE
import platform
import traceback
import threading

CALCULATING = -1
class Tracerouter(threading.Thread):
    def __init__(self):
        self.ready = False
        self.tr_cmd = CALCULATING
        self.routes = {}
        self.q_work = threading.Condition()
        self.queue = []
        threading.Thread.__init__(self)
        self.setDaemon(True)

    def run(self):
        self.setup()
        self.do_traceroutes()

    def setup(self):
        if platform.system() == "Windows":
            tr_cmd = ["tracert"]
            use_shell = True
        else:
            tr_cmd = ["traceroute"]
            use_shell = False

        try:
            run = Popen(["mtr", "--report", "-n", "localhost"],
                        shell=use_shell, stdout=PIPE)
            test = run.stdout.read()
            if "1" in test:
                tr_cmd = ["mtr", "--report", "--report-cycles", "2"]
                # print "mtr works..."
        except:
            try:
                run = Popen(tr_cmd + [ "localhost"], 
                            shell=use_shell, stdout=PIPE)
                test = run.stdout.read()
            except:
                print traceback.format_exc()
                tr_cmd = None
        self.tr_cmd = tr_cmd
        self.use_shell = use_shell
        self.ready = True
        print "ready"

    def do_traceroutes(self):
        while True:

            try:
                target_ip = self.get_from_queue()
                run = Popen(self.tr_cmd + ["-n", target_ip], stdout=PIPE)
                self.routes[target_ip] = run.stdout.read()
            except:
                traceback.print_exc() 

    def get_from_queue(self):
        # Wait til there's something in the queue
        self.q_work.acquire()
        if len(self.queue) == 0:
            self.q_work.wait()
        else:
            self.q_work.release()

        # Grab the next traceroute target off the queue
        target_ip = self.queue[0]
        del self.queue[0]
        print "got", target_ip
        return target_ip

    def enqueue(self, target):
        self.q_work.acquire()
        try:
            self.queue.append(target)
            self.routes[target] = "Waiting"
            self.q_work.notify()
        finally:
            self.q_work.release()
       

    def route_to(self, target_ip):
        if not self.tr_cmd:
            return False
        elif self.tr_cmd == CALCULATING:
            self.enqueue(target_ip)
            return "Waiting"
        elif target_ip in self.routes:
            return self.routes[target_ip]
        else:
            self.enqueue(target_ip)
            # This *probably* means we return "waiting", unless things happen
            # very quickly
            return self.routes[target_ip]

if __name__ == "__main__":
    tr = Tracerouter()
    tr.start()
    import time
    while True:
        x = tr.route_to("127.0.0.1")
        y = tr.route_to("www.eff.org")
        print x
        print y
        if y != "Waiting":
            break
        time.sleep(10)
