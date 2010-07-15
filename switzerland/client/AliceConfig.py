import getopt
import sys
import logging
import socket as s
import platform
import os
import errno
import stat

from switzerland.common import local_ip
from switzerland.common import util
log = logging.getLogger('')

if platform.system() != "Windows":
    default_pcap_logdir = "/var/log/switzerland-pcaps"
    default_logfile = "/var/log/switzerland-client.log"
else:
    default_pcap_logdir = "c:\switzerland\pcaplogs"
    default_logfile = "c:\switzerland\clientlog"

# These might turn into functions?
hostname = "hostname"
path = "path"
string = "string"
ip = "ip"

# This is a list of all the AliceConfig options:
# "name" -> {default, type, mutable, guiable}
alice_options = {\
"use_localhost_ip" : (False,                 bool,     False, False),\
"host"             : ("switzerland.eff.org", hostname, False, True),\
"port"             : (7778,                  int,      False, True),\
"interface"        : (None,                string,   False, True),\
"skew"             : (0.0,                   float,    False, True),\
"log_level"        : (logging.DEBUG,         int,      True,  True),\
"seriousness"      : (0,                     int,      True,  True),\
"do_cleaning"      : (True,                  bool,     True,  True),\
"use_ntp"          : (True,                  bool,     False, True),\
"filter_packets"   : (True,                  bool,     False, True),\
"keep_archives"    : (False,                 bool,     False, False),\
"ignore_nonlocal_packets" : (True,           bool,     False, False),\
"force_public_ip"  : (False,                 ip,       False, True),\
"force_private_ip" : (False,                 ip,       False, True),\
"pcap_playback"    : (False,                 bool,     False, False),\
"pcap_datalink"    : (1,                     int,      False, False),\
"logfile"          : (default_logfile,       path,     False, False),\
"pcap_logdir"      : (default_pcap_logdir,   path,     False, False),\
"allow_uncertain_time": (False,              bool,     False, False),\
"packet_buffer_size":(25000,                 int,      False, True),\
"quiet"            : (False,                 bool,     False, True),\
"debug_monotonicity":(True,                  bool,     False, False)\
}

class AliceConfig:
    def __init__(self, getopt=False, **keywords):

        # all of the variables above become attributes of AliceConfig;
        # we pick the value passed to this function (if there was one)
        # or the default value otherwise

        self.private_ip = None

        for variable in alice_options.keys():
            if variable in keywords:
                self.__dict__[variable] = keywords[variable]
            else:
                self.__dict__[variable] = alice_options[variable][0]

        if getopt:
            self.get_options()

        # Defaults remaining if getopt hasn't set things:
        if self.interface == None and getopt:
            self.interface = local_ip.get_interface()
            log.info("interface is now %s", self.interface)

        if self.force_private_ip and self.private_ip == None: # could have been set by getopt?
            self.private_ip = force_private_ip
        if self.private_ip == None:
            self.private_ip = local_ip.get_local_ip(self.interface)

    def get_options(self):
        if len(sys.argv) > 1 and sys.argv[1] == "help":
            self.usage()
        try:
            (opts, args) = \
                getopt.gnu_getopt(sys.argv[1:], 's:p:i:l:u:L:P:f:b:hqv',
                    ['server=', 'port=', 'interface=', 'ip=', 'help',
                    'private-ip=', 'public-ip=', 'logfile=', 'pcap-logs=',
                    'quiet', 'uncertain-time', 'verbose', 'buffer='])
        except getopt.GetoptError:
            self.usage()

        for opt, arg in opts:
            if opt in ('-s', '--server'):
                try:
                    if ":" in arg:
                        self.host, self.port = arg.split(":")
                        self.port = int(self.port)
                    else:
                        self.host = arg
                except ValueError:
                    self.usage(False)
                    print "Invalid argument for the", opt, "flag (specify a",
                    print "server to connect to)"
                    sys.exit(1)
            elif opt in ('-f', '--public-ip'):
                self.force_public_ip = arg
            elif opt in ('-p', '--port'):
                try:
                    self.port = int(arg)
                except ValueError:
                    self.usage(False)
                    print "Invalid argument for the", opt, "flag (need a",
                    print "port number"
                    sys.exit(1)
            elif opt in ('-i', '--interface'):
                self.interface = arg
            elif opt in ('-b', '--buffer'):
                try:
                    self.packet_buffer_size = int(arg)
                    assert(self.packet_buffer_size > 1)
                except:
                    print "Invalid packet buffer size (suggestion: 25000 or more)"
                    sys.exit(1)
            elif opt in ('-l', '--ip', '--private-ip'):
                self.private_ip = arg
            elif opt in ('-L', '--logfile'):
                self.logfile = arg
            elif opt in ('-P', '--pcap-logs'):
                self.pcap_logdir = arg
            elif opt in ('-h', '--help'):
                self.usage()
            elif opt in ('-q', '--quiet'):
                self.quiet = True
            elif opt in ('-u', '--uncertain-time'):
                self.allow_uncertain_time = True
                try:
                    self.manual_clock_error = float(arg)
                except ValueError:
                    self.usage(False)
                    print "Invalid argument for the", opt, "flag (please",
                    print "specify the maximum error of your clock in seconds)"
                    sys.exit(1)
            elif opt in ('-v', '--verbose'):
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
        print "  -l, --private-ip <ip>      (LAN) ip address of monitored interface"
        print "  -f, --public-ip <ip>       Force a public IP address.  Useful if you want to"
        print "                             tunnel to a server using ssh, tor,  a proxy, etc. "
        print "                             NB:this is disallowed by the default server config"
        print "  -u, --uncertain-time       Work without NTP.  This is dangerous;"
        print "       <time in seconds>     acurately specify the error in your system clock"
        print '  -L, --logfile <file>       Write a copy of the output to <file>. "-" for none'
        print "                             (defaults to " + default_logfile + ")"
        print "  -P, --pcap-logs <dir>      Sets the directory to which PCAPs of modified"
        print '                             packets will be written. "-" for none.'
        print "                             (defaults to " + default_pcap_logdir + ")"
        print "  -q, --quiet                Do not print output"
        if sys.argv[0].endswith('WebGUI.py'):
            print "  -a, --webaddr              Sets the ip address to run the Switzerland client"
            print "                             web server (defaults to 0.0.0.0)"
            print "  -w, --webport              Sets the port to run the Switzerland client"
            print "                             web server (defaults to 8080)"
            print "  -F, --fake                 Runs WebGUI in an off-network demonstration mode"
            print "                             with fake data"   
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
        except s.error:
            log.error("invalid local address format %s", `self.private_ip`)
            sys.exit(1)

        if self.pcap_logdir and self.pcap_logdir != "-":
            try:
                st = os.stat(self.pcap_logdir)
                if not stat.S_ISDIR(st[stat.ST_MODE]): # not a directory
                    log.error("%s isn't a directory", self.pcap_logdir)
                    log.error('Please make this a directory, or use "-P -" for no logging')
                    sys.exit(1)
            except OSError, e:
                if e.errno == errno.ENOENT: # no such file or directory
                    log.warn("PCAP log directory %s doesn't exist", self.pcap_logdir)
                    log.warn("trying to create it")
                    dir = os.path.split(self.pcap_logdir)
                    create = [dir[1]]
                    while ((not os.path.exists(dir[0])) and (not dir[0] == os.path.dirname(dir[0]))):
                        dir = os.path.split(dir[0])
                        create.insert(0, dir[1])
                    try:
                        dir=dir[0]
                        for newdir in create:
                            dir=os.path.join(dir, newdir)
                            os.mkdir(dir)
                    except OSError:
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

#vim: et ts=4 sw=4
