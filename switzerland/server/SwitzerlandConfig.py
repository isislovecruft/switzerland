import getopt
import sys

from switzerland.common import Protocol

class SwitzerlandConfig:
    def __init__(self,
        getopt=False,
        port=Protocol.default_port,
        sloppy=False,
        seriousness=0,
        keep_threads=False,
        keep_reconciliators=False,
        logging=True
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

        if getopt:
            self.get_options()

    def get_options(self):
        try:
            (opts, args) = \
                getopt.gnu_getopt(sys.argv[1:], 'p:h', \
                ['port=', 'help'])
        except:
            self.usage()

        for opt in opts:
            if opt[0] == '-p' or opt[0] == 'port':
                self.port = int(opt[1])
            elif opt[0] == '-h' or opt[0] == 'help':
                self.usage()

    def usage(self):
        print "%s [OPTIONS]" % sys.argv[0]
        print "server for switzerland network traffic auditing system"
        print
        print "  -h, --help                 print usage info"
        print "  -p, --port <port number>   port to listen on"
        sys.exit(0)

