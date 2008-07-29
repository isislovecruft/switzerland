import getopt
import sys
import platform

from switzerland.common import Protocol

if platform.system() != "Windows":
  default_pcap_logdir = "/var/log/switzerland-pcaps"
  default_logfile = "/var/log/switzerland-server.log"
else:
  default_pcap_logdir = "c:\switzerland\pcaplogs"
  default_logfile = "c:\switzerland\serverlog"


class SwitzerlandConfig:
    def __init__(self,
        getopt=False,
        port=Protocol.default_port,
        sloppy=False,
        seriousness=0,
        keep_threads=False,
        keep_reconciliators=False,
        logging=True,
        logfile=default_logfile,
        pcap_logdir=default_pcap_logdir,
        allow_fake_ips=False,
        send_flow_status_updates=True
        ):
        self.port = port
        self.sloppy = sloppy # Yes if we expect clients to send us flows that
                             # shouldn't be here.  True for some test cases
                             # perhaps, but not True in general.
        self.keep_threads = keep_threads # (Keep threads around even after they've
                                         # finished ; used for unit tests)
        self.keep_reconciliators = keep_reconciliators
        self.seriousness_threshold = seriousness
        self.logging = logging
        self.pcap_logdir = pcap_logdir
        self.logfile = logfile
        self.allow_fake_ips = allow_fake_ips
        self.send_flow_status_updates = send_flow_status_updates

        if getopt:
            self.get_options()

    def get_options(self):
        try:
            (opts, args) = \
                getopt.gnu_getopt(sys.argv[1:], 'p:hL:P:', \
                ['port=', 'help'])
        except:
            self.usage()

        for opt in opts:
            if opt[0] == '-p' or opt[0] == 'port':
                self.port = int(opt[1])
            elif opt[0] == '-h' or opt[0] == 'help':
                self.usage()
            elif opt[0] == '-L' or opt[0] == 'logfile':
                 self.logfile = opt[1]
            elif opt[0] == '-P' or opt[0] == 'pcap-logs':
                 self.pcap_logdir = opt[1]


    def usage(self):
        print "%s [OPTIONS]" % sys.argv[0]
        print "server for switzerland network traffic auditing system"
        print
        print "  -h, --help                 print usage info"
        print "  -p, --port <port number>   port to listen on"
        print '  -L, --logfile <file>       Write a copy of the output to <file>. "-" for none'
        print "                             (defaults to " + default_logfile + ")"
        print "  -P, --pcap-logs <dir>      Sets the directory to which PCAPs of modified"
        print '                             packets will be written. "-" for none.'
        print "                             (defaults to " + default_pcap_logdir + ")"

        sys.exit(0)

