import getopt
import sys
import logging
import socket as s
import platform

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
          self.private_ip = local_ip.get_local_ip()

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
          if opt[0] == '-s' or opt[0] == 'server':
              self.host = opt[1]
          elif opt[0] == '-p' or opt[0] == 'port':
              self.port = int(opt[1])
          elif opt[0] == '-i' or opt[0] == 'interface':
              self.interface = opt[1]
          elif opt[0] == '-l' or opt[0] == 'ip':
              self.private_ip = opt[1]
          elif opt[0] == '-L' or opt[0] == 'logfile':
              self.logfile = opt[1]
          elif opt[0] == '-P' or opt[0] == 'pcap-logs':
              self.pcap_logdir = opt[1]
          elif opt[0] == '-h' or opt[0] == 'help':
              self.usage()
          elif opt[0] == "-q" or opt[0] == 'quiet':
              self.quiet = True
          elif opt[0] == '-u' or opt[0] == 'uncertain-time':
              self.allow_uncertain_time = True
              self.manual_clock_error = float(opt[1])
          elif opt[0] == "-v" or opt[0] == "verbose":
              self.log_level -= (logging.INFO - logging.DEBUG)

    def usage(self):
        print 
        print "%s [OPTIONS]" % sys.argv[0]
        print 
        print "This is the client for EFF's Switzerland network traffic auditing system"
        print
        print "  -h, --help                 Print usage info"
        print "  -s, --server <host>        Switzerland server"
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
        sys.exit(0)

    def check(self):
        if not self.host:
            self.host = "switzerland.eff.org"
            log.info("no switzerland server specified, defaulting to %s" % self.host)
        
        # check for valid ip address
        try:
          s.inet_aton(self.private_ip)
        except:
          log.error("invalid local address format %s", `self.private_ip`)
          sys.exit(1) # bail out if we don't have one

        if self.pcap_logdir and self.pcap_logdir != "-" \
           and not util.writable(self.pcap_logdir):
          log.error("Cannot write to PCAP log directory %s", self.pcap_logdir)
          log.error("Change its permissions or specify another directory with -P")
          log.error('Use "-P -" for no logging')
          sys.exit(1)
 
#vim: et ts=4
