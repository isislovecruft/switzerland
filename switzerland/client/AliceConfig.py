import getopt
import sys
import logging
import socket as s
import platform
import os
import errno
from stat import *

from switzerland.common import local_ip
from switzerland.common import util
log = logging.getLogger('')

if platform.system() != "Windows":
    default_pcap_logdir = "/var/log/switzerland-pcaps"
    default_logfile = "/var/log/switzerland-client.log"
else:
    default_pcap_logdir = "c:\switzerland\pcaplogs"
    default_logfile = "c:\switzerland\clientlog"

class AliceConfig:
    def __init__(self,
        use_localhost_ip=False,
        host=None,
        port=7778,
        interface=None,
        skew=0.0,
        log_level=logging.DEBUG,
        seriousness=0,
        do_cleaning=True,
        use_ntp=True,
        filter_packets=True,
        keep_archives=False,
        ignore_nonlocal_packets=True,
        getopt=False,
        force_public_ip=False,
        force_private_ip=False,
        pcap_playback=None,
        pcap_datalink=0,
        logfile=default_logfile,
        pcap_logdir=default_pcap_logdir
        ):
        self.host = host
        self.port = port 
        self.interface = interface

        self.use_localhost_ip = use_localhost_ip
        self.skew = skew
        self.seriousness = seriousness
        self.log_level = log_level
        self.do_cleaning = do_cleaning
        self.use_ntp = use_ntp
        self.filter_packets = filter_packets
        self.keep_archives = keep_archives
        self.ignore_nonlocal_packets = ignore_nonlocal_packets
        self.force_public_ip = force_public_ip
        self.force_private_ip = force_private_ip
        self.private_ip = None
        self.pcap_playback = pcap_playback
        self.pcap_datalink = pcap_datalink
        self.allow_uncertain_time = False
        self.debug_monotonicity = True
        self.pcap_logdir = pcap_logdir
        self.logfile = logfile
        self.quiet = False

        if getopt:
            self.get_options()

        # defaults remain in if getopt hasn't set things:
        if self.interface == None and getopt:
          self.interface = local_ip.get_interface()
          log.info("interface is now %s", self.interface)

        if force_private_ip and self.private_ip == None: # could have been set by getopt?
            self.private_ip = force_private_ip
        if self.private_ip == None:
            self.private_ip = local_ip.get_local_ip(self.interface)

    def get_options(self):
        if len(sys.argv) > 1 and sys.argv[1] == "help":
            self.usage()
        try:
            (opts, args) = \
                getopt.gnu_getopt(sys.argv[1:], 's:p:i:l:u:L:P:hq', \
                ['server=', 'port=', 'interface=', 'ip', 'help'])
        except:
            self.usage()

        for opt in opts:
            if opt[0] in ('-s', '--server'):
                try:
                    if ":" in opt[1]:
                        self.host, self.port = opt[1].split(":")
                        self.port = int(self.port)
                    else:
                        self.host = opt[1]
                except:
                    self.usage(False)
                    print "Invalid argument for the", opt[0], "flag (specify a",
                    print "server to connect to)"
                    sys.exit(1)
            elif opt[0] in ('-p', '--port'):
                try:
                    self.port = int(opt[1])
                except:
                    self.usage(False)
                    print "Invalid argument for the", opt[0], "flag (need a",
                    print "port number"
                    sys.exit(1)
            elif opt[0] in ('-i', '--interface'):
                self.interface = opt[1]
            elif opt[0] in ('-l', '--ip'):
                self.private_ip = opt[1]
            elif opt[0] in ('-L', '--logfile'):
                self.logfile = opt[1]
            elif opt[0] in ('-P', '--pcap-logs'):
                self.pcap_logdir = opt[1]
            elif opt[0] in ('-h', '--help'):
                self.usage()
            elif opt[0] in ('-q', '--quiet'):
                self.quiet = True
            elif opt[0] in ('-u', '--uncertain-time'):
                self.allow_uncertain_time = True
                try:
                    self.manual_clock_error = float(opt[1])
                except:
                    self.usage(False)
                    print "Invalid argument for the", opt[0], "flag (please",
                    print "specify the maximum error of your clock in seconds)"
                    sys.exit(1)
            elif opt[0] in ('-v', '--verbose'):
                self.log_level -= (logging.INFO - logging.DEBUG)

    def usage(self, exit=True):
        print 
        print "%s [OPTIONS]" % sys.argv[0]
        print 
        print "This is the client for EFF's Switzerland network traffic auditing system"
        print
        print "  -h, --help                 Print usage info"
        print "  -s, --server <host[:port]> Switzerland server [and port]"
        print "  -p, --port <port number>   Switzerland server port"
        print "  -i, --interface <iface>    Interface on which to monitor traffic"
        print "  -l, --ip <ip>              (Local) ip address of monitored interface"
        print "  -u, --uncertain-time       Work without NTP.  This is dangerous;"
        print "       <time in seconds>     acurately specify the error in your system clock" 
        print '  -L, --logfile <file>       Write a copy of the output to <file>. "-" for none'
        print "                             (defaults to " + default_logfile + ")"
        print "  -P, --pcap-logs <dir>      Sets the directory to which PCAPs of modified"
        print '                             packets will be written. "-" for none.'
        print "                             (defaults to " + default_pcap_logdir + ")"
        print "  -q, --quiet                Do not print output"
        print
        if exit: sys.exit(0)
            
                            
    def check(self):
        if not self.host:
            self.host = "switzerland.eff.org"
            log.info("no switzerland server specified, defaulting to %s" % self.host)
        
        # check for a valid ip address
        if self.private_ip == None:
            log.error("Switzerland wasn't able to determine your local IP address.")
            log.error("Make sure you're online; if you are, use the -l flag to specify you IP")
            sys.exit(1)
        try:
            s.inet_aton(self.private_ip)
        except:
            log.error("invalid local address format %s", `self.private_ip`)
            sys.exit(1) 

        if self.pcap_logdir and self.pcap_logdir != "-":
            try:
                st = os.stat(self.pcap_logdir)
                if not S_ISDIR(st[ST_MODE]): # not a directory
                    log.error("%s isn't a directory", self.pcap_logdir)
                    log.error('Please make this a directory, or use "-P -" for no logging')
                    sys.exit(1)
            except OSError, e:
                if e.errno == errno.ENOENT: # no such file or directory
                    log.warn("PCAP log directory %s doesn't exist", self.pcap_logdir)
                    log.warn("trying to create it")
                    dir=os.path.split(self.pcap_logdir)
                    create=[dir[1]]
                    while ((not os.path.exists(dir[0])) and (not dir[0]== os.path.dirname(dir[0]))):
                        dir=os.path.split(dir[0])
                        create.insert(0, dir[1])
                    try:
                        dir=dir[0]
                        for newdir in create:
                            dir=os.path.join(dir, newdir)
                            os.mkdir(dir)
                    except:
                        log.error("can't create PCAP log directory")
                        log.error('Please create it, or use "-P -" for no logging')
                        sys.exit(1)
                else: # can't stat, that's probably bad
                    log.error("can't stat PCAP log directory %s: %s", self.pcap_logdir, str(e))
                    log.error('Use "-P -" for no logging')
                    sys.exit(1)
            if not util.writable(self.pcap_logdir):
                log.error("Cannot write to PCAP log directory %s", self.pcap_logdir)
                log.error("Change its permissions or specify another directory with -P")
                log.error('Use "-P -" for no logging')
                sys.exit(1)
 
#vim: et ts=4
