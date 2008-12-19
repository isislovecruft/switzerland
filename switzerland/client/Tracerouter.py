#!/usr/bin/env python

from subprocess import Popen, PIPE
import platform
import traceback

class Tracerouter:
    def __init__(self):
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
                print "mtr works..."
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
            

    def route_to(self, target_ip):
        if not self.tr_cmd:
            return False
        run = Popen(self.tr_cmd + ["-n", target_ip], stdout=PIPE)
        return run.stdout.read()

if __name__ == "__main__":
    tr = Tracerouter()
    print tr.route_to("127.0.0.1")
    print tr.route_to("www.eff.org")
