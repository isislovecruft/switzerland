## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import os,time,struct,re,socket,new
from select import select

from scapy.layers.l2 import *
from scapy.fields import *
from scapy.packet import *
from scapy.volatile import *
from scapy.config import conf
from scapy.sendrecv import sr,sr1,srp1
from scapy.plist import PacketList,SndRcvList

import scapy.as_resolvers


####################
## IP Tools class ##
####################

class IPTools:
    """Add more powers to a class that have a "src" attribute."""
    def whois(self):
        os.system("whois %s" % self.src)
    def ottl(self):
        t = [32,64,128,255]+[self.ttl]
        t.sort()
        return t[t.index(self.ttl)+1]
    def hops(self):
        return self.ottl()-self.ttl-1 



class IPoptionsField(StrField):
    def i2m(self, pkt, x):
        return x+"\x00"*(3-((len(x)+3)%4))
    def getfield(self, pkt, s):
        opsz = (pkt.ihl-5)*4
        if opsz < 0:
            warning("bad ihl (%i). Assuming ihl=5"%pkt.ihl)
            opsz = 0
        return s[opsz:],s[:opsz]
    def randval(self):
        return RandBin(RandNum(0,39))


TCPOptions = (
              { 0 : ("EOL",None),
                1 : ("NOP",None),
                2 : ("MSS","!H"),
                3 : ("WScale","!B"),
                4 : ("SAckOK",None),
                5 : ("SAck","!"),
                8 : ("Timestamp","!II"),
                14 : ("AltChkSum","!BH"),
                15 : ("AltChkSumOpt",None)
                },
              { "EOL":0,
                "NOP":1,
                "MSS":2,
                "WScale":3,
                "SAckOK":4,
                "SAck":5,
                "Timestamp":8,
                "AltChkSum":14,
                "AltChkSumOpt":15,
                } )

class TCPOptionsField(StrField):
    islist=1
    def getfield(self, pkt, s):
        opsz = (pkt.dataofs-5)*4
        if opsz < 0:
            warning("bad dataofs (%i). Assuming dataofs=5"%pkt.dataofs)
            opsz = 0
        return s[opsz:],self.m2i(pkt,s[:opsz])
    def m2i(self, pkt, x):
        opt = []
        while x:
            onum = ord(x[0])
            if onum == 0:
                opt.append(("EOL",None))
                x=x[1:]
                break
            if onum == 1:
                opt.append(("NOP",None))
                x=x[1:]
                continue
            olen = ord(x[1])
            if olen < 2:
                warning("Malformed TCP option (announced length is %i)" % olen)
                olen = 2
            oval = x[2:olen]
            if TCPOptions[0].has_key(onum):
                oname, ofmt = TCPOptions[0][onum]
                if onum == 5: #SAck
                    ofmt += "%iI" % (len(oval)/4)
                if ofmt and struct.calcsize(ofmt) == len(oval):
                    oval = struct.unpack(ofmt, oval)
                    if len(oval) == 1:
                        oval = oval[0]
                opt.append((oname, oval))
            else:
                opt.append((onum, oval))
            x = x[olen:]
        return opt
    
    def i2m(self, pkt, x):
        opt = ""
        for oname,oval in x:
            if type(oname) is str:
                if oname == "NOP":
                    opt += "\x01"
                    continue
                elif oname == "EOL":
                    opt += "\x00"
                    continue
                elif TCPOptions[1].has_key(oname):
                    onum = TCPOptions[1][oname]
                    ofmt = TCPOptions[0][onum][1]
                    if onum == 5: #SAck
                        ofmt += "%iI" % len(oval)
                    if ofmt is not None and (type(oval) is not str or "s" in ofmt):
                        if type(oval) is not tuple:
                            oval = (oval,)
                        oval = struct.pack(ofmt, *oval)
                else:
                    warning("option [%s] unknown. Skipped."%oname)
                    continue
            else:
                onum = oname
                if type(oval) is not str:
                    warning("option [%i] is not string."%onum)
                    continue
            opt += chr(onum)+chr(2+len(oval))+oval
        return opt+"\x00"*(3-((len(opt)+3)%4))
    def randval(self):
        return [] # XXX
    

class ICMPTimeStampField(IntField):
    re_hmsm = re.compile("([0-2]?[0-9])[Hh:](([0-5]?[0-9])([Mm:]([0-5]?[0-9])([sS:.]([0-9]{0,3}))?)?)?$")
    def i2repr(self, pkt, val):
        if val is None:
            return "--"
        else:
            sec, milli = divmod(val, 1000)
            min, sec = divmod(sec, 60)
            hour, min = divmod(min, 60)
            return "%d:%d:%d.%d" %(hour, min, sec, int(milli))
    def any2i(self, pkt, val):
        if type(val) is str:
            hmsms = self.re_hmsm.match(val)
            if hmsms:
                h,_,m,_,s,_,ms = hmsms = hmsms.groups()
                ms = int(((ms or "")+"000")[:3])
                val = ((int(h)*60+int(m or 0))*60+int(s or 0))*1000+ms
            else:
                val = 0
        elif val is None:
            val = int((time.time()%(24*60*60))*1000)
        return val


class IP(Packet, IPTools):
    name = "IP"
    fields_desc = [ BitField("version" , 4 , 4),
                    BitField("ihl", None, 4),
                    XByteField("tos", 0),
                    ShortField("len", None),
                    ShortField("id", 1),
                    FlagsField("flags", 0, 3, ["MF","DF","evil"]),
                    BitField("frag", 0, 13),
                    ByteField("ttl", 64),
                    ByteEnumField("proto", 0, IP_PROTOS),
                    XShortField("chksum", None),
                    #IPField("src", "127.0.0.1"),
                    Emph(SourceIPField("src","dst")),
                    Emph(IPField("dst", "127.0.0.1")),
                    IPoptionsField("options", "") ]
    def post_build(self, p, pay):
        ihl = self.ihl
        if ihl is None:
            ihl = len(p)/4
            p = chr(((self.version&0xf)<<4) | ihl&0x0f)+p[1:]
        if self.len is None:
            l = len(p)+len(pay)
            p = p[:2]+struct.pack("!H", l)+p[4:]
        if self.chksum is None:
            ck = checksum(p)
            p = p[:10]+chr(ck>>8)+chr(ck&0xff)+p[12:]
        return p+pay

    def extract_padding(self, s):
        l = self.len - (self.ihl << 2)
        return s[:l],s[l:]

    def send(self, s, slp=0):
        for p in self:
            try:
                s.sendto(str(p), (p.dst,0))
            except socket.error, msg:
                log_runtime.error(msg)
            if slp:
                time.sleep(slp)
    def route(self):
        dst = self.dst
        if isinstance(dst,Gen):
            dst = iter(dst).next()
        return conf.route.route(dst)
    def hashret(self):
        if ( (self.proto == socket.IPPROTO_ICMP)
             and (isinstance(self.payload, ICMP))
             and (self.payload.type in [3,4,5,11,12]) ):
            return self.payload.payload.hashret()
        else:
            if conf.checkIPsrc and conf.checkIPaddr:
                return strxor(inet_aton(self.src),inet_aton(self.dst))+struct.pack("B",self.proto)+self.payload.hashret()
            else:
                return struct.pack("B", self.proto)+self.payload.hashret()
    def answers(self, other):
        if not isinstance(other,IP):
            return 0
        if conf.checkIPaddr and (self.dst != other.src):
            return 0
        if ( (self.proto == socket.IPPROTO_ICMP) and
             (isinstance(self.payload, ICMP)) and
             (self.payload.type in [3,4,5,11,12]) ):
            # ICMP error message
            return self.payload.payload.answers(other)

        else:
            if ( (conf.checkIPaddr and (self.src != other.dst)) or
                 (self.proto != other.proto) ):
                return 0
            return self.payload.answers(other.payload)
    def mysummary(self):
        s = self.sprintf("%IP.src% > %IP.dst% %IP.proto%")
        if self.frag:
            s += " frag:%i" % self.frag
        return s
                 
    

class TCP(Packet):
    name = "TCP"
    fields_desc = [ ShortEnumField("sport", 20, TCP_SERVICES),
                    ShortEnumField("dport", 80, TCP_SERVICES),
                    IntField("seq", 0),
                    IntField("ack", 0),
                    BitField("dataofs", None, 4),
                    BitField("reserved", 0, 4),
                    FlagsField("flags", 0x2, 8, "FSRPAUEC"),
                    ShortField("window", 8192),
                    XShortField("chksum", None),
                    ShortField("urgptr", 0),
                    TCPOptionsField("options", {}) ]
    def post_build(self, p, pay):
        p += pay
        dataofs = self.dataofs
        if dataofs is None:
            dataofs = 5+((len(self.get_field("options").i2m(self,self.options))+3)/4)
            p = p[:12]+chr((dataofs << 4) | ord(p[12])&0x0f)+p[13:]
        if self.chksum is None:
            if isinstance(self.underlayer, IP):
                if self.underlayer.len is not None:
                    ln = self.underlayer.len-20
                else:
                    ln = len(p)
                psdhdr = struct.pack("!4s4sHH",
                                     inet_aton(self.underlayer.src),
                                     inet_aton(self.underlayer.dst),
                                     self.underlayer.proto,
                                     ln)
                ck=checksum(psdhdr+p)
                p = p[:16]+struct.pack("!H", ck)+p[18:]
            elif isinstance(self.underlayer, IPv6) or isinstance(self.underlayer, _IPv6OptionHeader):
                ck = in6_chksum(socket.IPPROTO_TCP, self.underlayer, p)
                p = p[:16]+struct.pack("!H", ck)+p[18:]
            else:
                warning("No IP underlayer to compute checksum. Leaving null.")
        return p
    def hashret(self):
        if conf.checkIPsrc:
            return struct.pack("H",self.sport ^ self.dport)+self.payload.hashret()
        else:
            return self.payload.hashret()
    def answers(self, other):
        if not isinstance(other, TCP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.dport) and
                    (self.dport == other.sport)):
                return 0
        if (abs(other.seq-self.ack) > 2+len(other.payload)):
            return 0
        return 1
    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("TCP %IP.src%:%TCP.sport% > %IP.dst%:%TCP.dport% %TCP.flags%")
        elif isinstance(self.underlayer, IPv6):
            return self.underlayer.sprintf("TCP %IPv6.src%:%TCP.sport% > %IPv6.dst%:%TCP.dport% %TCP.flags%")
        else:
            return self.sprintf("TCP %TCP.sport% > %TCP.dport% %TCP.flags%")

class UDP(Packet):
    name = "UDP"
    fields_desc = [ ShortEnumField("sport", 53, UDP_SERVICES),
                    ShortEnumField("dport", 53, UDP_SERVICES),
                    ShortField("len", None),
                    XShortField("chksum", None), ]
    def post_build(self, p, pay):
        p += pay
        l = self.len
        if l is None:
            l = len(p)
            p = p[:4]+struct.pack("!H",l)+p[6:]
        if self.chksum is None:
            if isinstance(self.underlayer, IP):
                if self.underlayer.len is not None:
                    ln = self.underlayer.len-20
                else:
                    ln = len(p)
                psdhdr = struct.pack("!4s4sHH",
                                     inet_aton(self.underlayer.src),
                                     inet_aton(self.underlayer.dst),
                                     self.underlayer.proto,
                                     ln)
                ck=checksum(psdhdr+p)
                p = p[:6]+struct.pack("!H", ck)+p[8:]
            elif isinstance(self.underlayer, IPv6) or isinstance(self.underlayer, _IPv6OptionHeader):
                ck = in6_chksum(socket.IPPROTO_UDP, self.underlayer, p)
                p = p[:6]+struct.pack("!H", ck)+p[8:]
            else:
                warning("No IP underlayer to compute checksum. Leaving null.")
        return p
    def extract_padding(self, s):
        l = self.len - 8
        return s[:l],s[l:]
    def hashret(self):
        return self.payload.hashret()
    def answers(self, other):
        if not isinstance(other, UDP):
            return 0
        if conf.checkIPsrc:
            if self.dport != other.sport:
                return 0
        return self.payload.answers(other.payload)
    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("UDP %IP.src%:%UDP.sport% > %IP.dst%:%UDP.dport%")
        elif isinstance(self.underlayer, IPv6):
            return self.underlayer.sprintf("UDP %IPv6.src%:%UDP.sport% > %IPv6.dst%:%UDP.dport%")
        else:
            return self.sprintf("UDP %UDP.sport% > %UDP.dport%")    

icmptypes = { 0 : "echo-reply",
              3 : "dest-unreach",
              4 : "source-quench",
              5 : "redirect",
              8 : "echo-request",
              9 : "router-advertisement",
              10 : "router-solicitation",
              11 : "time-exceeded",
              12 : "parameter-problem",
              13 : "timestamp-request",
              14 : "timestamp-reply",
              15 : "information-request",
              16 : "information-response",
              17 : "address-mask-request",
              18 : "address-mask-reply" }

class ICMP(Packet):
    name = "ICMP"
    fields_desc = [ ByteEnumField("type",8, icmptypes),
                    ByteField("code",0),
                    XShortField("chksum", None),
                    ConditionalField(XShortField("id",0),  lambda pkt:pkt.type in [0,8,13,14,15,16]),
                    ConditionalField(XShortField("seq",0), lambda pkt:pkt.type in [0,8,13,14,15,16]),
                    ConditionalField(ICMPTimeStampField("ts_ori", None), lambda pkt:pkt.type in [13,14]),
                    ConditionalField(ICMPTimeStampField("ts_rx", None), lambda pkt:pkt.type in [13,14]),
                    ConditionalField(ICMPTimeStampField("ts_tx", None), lambda pkt:pkt.type in [13,14]),
                    ConditionalField(IPField("gw","0.0.0.0"),  lambda pkt:pkt.type==5),
                    ConditionalField(ByteField("ptr",0),   lambda pkt:pkt.type==12),
                    ConditionalField(X3BytesField("reserved",0), lambda pkt:pkt.type==12),
                    ConditionalField(IntField("unused",0), lambda pkt:pkt.type not in [0,5,8,12,13,14,15,16]),
                    ]
    def post_build(self, p, pay):
        p += pay
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2]+chr(ck>>8)+chr(ck&0xff)+p[4:]
        return p
    
    def hashret(self):
        return struct.pack("HH",self.id,self.seq)+self.payload.hashret()
    def answers(self, other):
        if not isinstance(other,ICMP):
            return 0
        if ( (other.type,self.type) in [(8,0),(13,14),(15,16),(17,18)] and
             self.id == other.id and
             self.seq == other.seq ):
            return 1
        return 0

    def guess_payload_class(self, payload):
        if self.type in [3,4,5,11,12]:
            return IPerror
        else:
            return None
    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("ICMP %IP.src% > %IP.dst% %ICMP.type% %ICMP.code%")
        else:
            return self.sprintf("ICMP %ICMP.type% %ICMP.code%")
    
        



class IPerror(IP):
    name = "IP in ICMP"
    def answers(self, other):
        if not isinstance(other, IP):
            return 0
        if not ( ((conf.checkIPsrc == 0) or (self.dst == other.dst)) and
                 (self.src == other.src) and
                 ( ((conf.checkIPID == 0)
                    or (self.id == other.id)
                    or (conf.checkIPID == 1 and self.id == socket.htons(other.id)))) and
                 (self.proto == other.proto) ):
            return 0
        return self.payload.answers(other.payload)
    def mysummary(self):
        return Packet.mysummary(self)


class TCPerror(TCP):
    name = "TCP in ICMP"
    def answers(self, other):
        if not isinstance(other, TCP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.sport) and
                    (self.dport == other.dport)):
                return 0
        if conf.check_TCPerror_seqack:
            if self.seq is not None:
                if self.seq != other.seq:
                    return 0
            if self.ack is not None:
                if self.ack != other.ack:
                    return 0
        return 1
    def mysummary(self):
        return Packet.mysummary(self)


class UDPerror(UDP):
    name = "UDP in ICMP"
    def answers(self, other):
        if not isinstance(other, UDP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.sport) and
                    (self.dport == other.dport)):
                return 0
        return 1
    def mysummary(self):
        return Packet.mysummary(self)

                    

class ICMPerror(ICMP):
    name = "ICMP in ICMP"
    def answers(self, other):
        if not isinstance(other,ICMP):
            return 0
        if not ((self.type == other.type) and
                (self.code == other.code)):
            return 0
        if self.code in [0,8,13,14,17,18]:
            if (self.id == other.id and
                self.seq == other.seq):
                return 1
            else:
                return 0
        else:
            return 1
    def mysummary(self):
        return Packet.mysummary(self)

bind_layers( Ether,         IP,            type=2048)
bind_layers( CookedLinux,   IP,            proto=2048)
bind_layers( GRE,           IP,            proto=2048)
bind_layers( SNAP,          IP,            code=2048)
bind_layers( IPerror,       IPerror,       frag=0, proto=4)
bind_layers( IPerror,       ICMPerror,     frag=0, proto=1)
bind_layers( IPerror,       TCPerror,      frag=0, proto=6)
bind_layers( IPerror,       UDPerror,      frag=0, proto=17)
bind_layers( IP,            IP,            frag=0, proto=4)
bind_layers( IP,            ICMP,          frag=0, proto=1)
bind_layers( IP,            TCP,           frag=0, proto=6)
bind_layers( IP,            UDP,           frag=0, proto=17)
bind_layers( IP,            GRE,           frag=0, proto=47)

conf.l2types.register(101, IP)
conf.l2types.register_num2layer(12, IP)

conf.l3types.register(ETH_P_IP, IP)
conf.l3types.register_num2layer(ETH_P_ALL, IP)


conf.neighbor.register_l3(Ether, IP, lambda l2,l3: getmacbyip(l3.dst))


###################
## Fragmentation ##
###################

@conf.commands.register
def fragment(pkt, fragsize=1480):
    """Fragment a big IP datagram"""
    fragsize = (fragsize+7)/8*8
    lst = []
    for p in pkt:
        s = str(p[IP].payload)
        nb = (len(s)+fragsize-1)/fragsize
        for i in range(nb):            
            q = p.copy()
            del(q[IP].payload)
            del(q[IP].chksum)
            del(q[IP].len)
            if i == nb-1:
                q[IP].flags &= ~1
            else:
                q[IP].flags |= 1 
            q[IP].frag = i*fragsize/8
            r = Raw(load=s[i*fragsize:(i+1)*fragsize])
            r.overload_fields = p[IP].payload.overload_fields.copy()
            q.add_payload(r)
            lst.append(q)
    return lst

def overlap_frag(p, overlap, fragsize=8, overlap_fragsize=None):
    if overlap_fragsize is None:
        overlap_fragsize = fragsize
    q = p.copy()
    del(q[IP].payload)
    q[IP].add_payload(overlap)

    qfrag = fragment(q, overlap_fragsize)
    qfrag[-1][IP].flags |= 1
    return qfrag+fragment(p, fragsize)

@conf.commands.register
def defrag(plist):
    """defrag(plist) -> ([not fragmented], [defragmented],
                  [ [bad fragments], [bad fragments], ... ])"""
    frags = {}
    nofrag = PacketList()
    for p in plist:
        ip = p[IP]
        if IP not in p:
            nofrag.append(p)
            continue
        if ip.frag == 0 and ip.flags & 1 == 0:
            nofrag.append(p)
            continue
        uniq = (ip.id,ip.src,ip.dst,ip.proto)
        if uniq in frags:
            frags[uniq].append(p)
        else:
            frags[uniq] = PacketList([p])
    defrag = []
    missfrag = []
    for lst in frags.itervalues():
        lst.sort(lambda x,y:cmp(x.frag, y.frag))
        p = lst[0]
        if p.frag > 0:
            missfrag.append(lst)
            continue
        p = p.copy()
        if Padding in p:
            del(p[Padding].underlayer.payload)
        ip = p[IP]
        if ip.len is None or ip.ihl is None:
            clen = len(ip.payload)
        else:
            clen = ip.len - (ip.ihl<<2)
        txt = Raw()
        for q in lst[1:]:
            if clen != q.frag<<3:
                if clen > q.frag<<3:
                    warning("Fragment overlap (%i > %i) %r || %r ||  %r" % (clen, q.frag<<3, p,txt,q))
                missfrag.append(lst)
                txt = None
                break
            if q[IP].len is None or q[IP].ihl is None:
                clen += len(q[IP].payload)
            else:
                clen += q[IP].len - (q[IP].ihl<<2)
            if Padding in q:
                del(q[Padding].underlayer.payload)
            txt.add_payload(q[IP].payload.copy())
            
        if txt is None:
            continue

        ip.flags &= ~1 # !MF
        del(ip.chksum)
        del(ip.len)
        p = p/txt
        defrag.append(p)
    defrag2=PacketList()
    for p in defrag:
        defrag2.append(p.__class__(str(p)))
    return nofrag,defrag2,missfrag
            
@conf.commands.register
def defragment(plist):
    """defrag(plist) -> plist defragmented as much as possible """
    frags = {}
    final = []

    pos = 0
    for p in plist:
        p._defrag_pos = pos
        pos += 1
        if IP in p:
            ip = p[IP]
            if ip.frag != 0 or ip.flags & 1:
                ip = p[IP]
                uniq = (ip.id,ip.src,ip.dst,ip.proto)
                if uniq in frags:
                    frags[uniq].append(p)
                else:
                    frags[uniq] = [p]
                continue
        final.append(p)

    defrag = []
    missfrag = []
    for lst in frags.itervalues():
        lst.sort(lambda x,y:cmp(x.frag, y.frag))
        p = lst[0]
        if p.frag > 0:
            missfrag += lst
            continue
        p = p.copy()
        if Padding in p:
            del(p[Padding].underlayer.payload)
        ip = p[IP]
        if ip.len is None or ip.ihl is None:
            clen = len(ip.payload)
        else:
            clen = ip.len - (ip.ihl<<2)
        txt = Raw()
        for q in lst[1:]:
            if clen != q.frag<<3:
                if clen > q.frag<<3:
                    warning("Fragment overlap (%i > %i) %r || %r ||  %r" % (clen, q.frag<<3, p,txt,q))
                missfrag += lst
                txt = None
                break
            if q[IP].len is None or q[IP].ihl is None:
                clen += len(q[IP].payload)
            else:
                clen += q[IP].len - (q[IP].ihl<<2)
            if Padding in q:
                del(q[Padding].underlayer.payload)
            txt.add_payload(q[IP].payload.copy())
            
        if txt is None:
            continue

        ip.flags &= ~1 # !MF
        del(ip.chksum)
        del(ip.len)
        p = p/txt
        p._defrag_pos = lst[-1]._defrag_pos
        defrag.append(p)
    defrag2=[]
    for p in defrag:
        q = p.__class__(str(p))
        q._defrag_pos = p._defrag_pos
        defrag2.append(q)
    final += defrag2
    final += missfrag
    final.sort(lambda x,y: cmp(x._defrag_pos, y._defrag_pos))
    for p in final:
        del(p._defrag_pos)

    if hasattr(plist, "listname"):
        name = "Defragmented %s" % plist.listname
    else:
        name = "Defragmented"
        
    
    return PacketList(final, name=name)
            
            
        

### Add timeskew_graph() method to PacketList
def _packetlist_timeskew_graph(self, ip, **kargs):
    """Tries to graph the timeskew between the timestamps and real time for a given ip"""
    res = map(lambda x: self._elt2pkt(x), self.res)
    b = filter(lambda x:x.haslayer(IP) and x.getlayer(IP).src == ip and x.haslayer(TCP), res)
    c = []
    for p in b:
        opts = p.getlayer(TCP).options
        for o in opts:
            if o[0] == "Timestamp":
                c.append((p.time,o[1][0]))
    if not c:
        warning("No timestamps found in packet list")
        return
    d = map(lambda (x,y): (x%2000,((x-c[0][0])-((y-c[0][1])/1000.0))),c)
    g = Gnuplot.Gnuplot()
    g.plot(Gnuplot.Data(d,**kargs))
    return g

PacketList.timeskew_graph = new.instancemethod(_packetlist_timeskew_graph, None, PacketList)


### Create a new packet list
class TracerouteResult(SndRcvList):
    def __init__(self, res=None, name="Traceroute", stats=None):
        PacketList.__init__(self, res, name, stats)
        self.graphdef = None
        self.graphASres = 0
        self.padding = 0
        self.hloc = None
        self.nloc = None

    def show(self):
        return self.make_table(lambda (s,r): (s.sprintf("%IP.dst%:{TCP:tcp%ir,TCP.dport%}{UDP:udp%ir,UDP.dport%}{ICMP:ICMP}"),
                                              s.ttl,
                                              r.sprintf("%-15s,IP.src% {TCP:%TCP.flags%}{ICMP:%ir,ICMP.type%}")))


    def get_trace(self):
        trace = {}
        for s,r in self.res:
            if IP not in s:
                continue
            d = s[IP].dst
            if d not in trace:
                trace[d] = {}
            trace[d][s[IP].ttl] = r[IP].src, ICMP not in r
        for k in trace.values():
            m = filter(lambda x:k[x][1], k.keys())
            if not m:
                continue
            m = min(m)
            for l in k.keys():
                if l > m:
                    del(k[l])
        return trace

    def trace3D(self):
        """Give a 3D representation of the traceroute.
        right button: rotate the scene
        middle button: zoom
        left button: move the scene
        left button on a ball: toggle IP displaying
        ctrl-left button on a ball: scan ports 21,22,23,25,80 and 443 and display the result"""
        trace = self.get_trace()
        import visual

        class IPsphere(visual.sphere):
            def __init__(self, ip, **kargs):
                visual.sphere.__init__(self, **kargs)
                self.ip=ip
                self.label=None
                self.setlabel(self.ip)
            def setlabel(self, txt,visible=None):
                if self.label is not None:
                    if visible is None:
                        visible = self.label.visible
                    self.label.visible = 0
                elif visible is None:
                    visible=0
                self.label=visual.label(text=txt, pos=self.pos, space=self.radius, xoffset=10, yoffset=20, visible=visible)
            def action(self):
                self.label.visible ^= 1

        visual.scene = visual.display()
        visual.scene.exit_on_close(0)
        start = visual.box()
        rings={}
        tr3d = {}
        for i in trace:
            tr = trace[i]
            tr3d[i] = []
            ttl = tr.keys()
            for t in range(1,max(ttl)+1):
                if t not in rings:
                    rings[t] = []
                if t in tr:
                    if tr[t] not in rings[t]:
                        rings[t].append(tr[t])
                    tr3d[i].append(rings[t].index(tr[t]))
                else:
                    rings[t].append(("unk",-1))
                    tr3d[i].append(len(rings[t])-1)
        for t in rings:
            r = rings[t]
            l = len(r)
            for i in range(l):
                if r[i][1] == -1:
                    col = (0.75,0.75,0.75)
                elif r[i][1]:
                    col = visual.color.green
                else:
                    col = visual.color.blue
                
                s = IPsphere(pos=((l-1)*visual.cos(2*i*visual.pi/l),(l-1)*visual.sin(2*i*visual.pi/l),2*t),
                             ip = r[i][0],
                             color = col)
                for trlst in tr3d.values():
                    if t <= len(trlst):
                        if trlst[t-1] == i:
                            trlst[t-1] = s
        forecol = colgen(0.625, 0.4375, 0.25, 0.125)
        for trlst in tr3d.values():
            col = forecol.next()
            start = (0,0,0)
            for ip in trlst:
                visual.cylinder(pos=start,axis=ip.pos-start,color=col,radius=0.2)
                start = ip.pos
        
        movcenter=None
        while 1:
            if visual.scene.kb.keys:
                k = visual.scene.kb.getkey()
                if k == "esc":
                    break
            if visual.scene.mouse.events:
                ev = visual.scene.mouse.getevent()
                if ev.press == "left":
                    o = ev.pick
                    if o:
                        if ev.ctrl:
                            if o.ip == "unk":
                                continue
                            savcolor = o.color
                            o.color = (1,0,0)
                            a,b=sendrecv.sr(IP(dst=o.ip)/TCP(dport=[21,22,23,25,80,443]),timeout=2)
                            o.color = savcolor
                            if len(a) == 0:
                                txt = "%s:\nno results" % o.ip
                            else:
                                txt = "%s:\n" % o.ip
                                for s,r in a:
                                    txt += r.sprintf("{TCP:%IP.src%:%TCP.sport% %TCP.flags%}{TCPerror:%IPerror.dst%:%TCPerror.dport% %IP.src% %ir,ICMP.type%}\n")
                            o.setlabel(txt, visible=1)
                        else:
                            if hasattr(o, "action"):
                                o.action()
                elif ev.drag == "left":
                    movcenter = ev.pos
                elif ev.drop == "left":
                    movcenter = None
            if movcenter:
                visual.scene.center -= visual.scene.mouse.pos-movcenter
                movcenter = visual.scene.mouse.pos
                
                
    def world_trace(self):
        from modules.geo import locate_ip
        ips = {}
        rt = {}
        ports_done = {}
        for s,r in self.res:
            ips[r.src] = None
            if s.haslayer(TCP) or s.haslayer(UDP):
                trace_id = (s.src,s.dst,s.proto,s.dport)
            elif s.haslayer(ICMP):
                trace_id = (s.src,s.dst,s.proto,s.type)
            else:
                trace_id = (s.src,s.dst,s.proto,0)
            trace = rt.get(trace_id,{})
            if not r.haslayer(ICMP) or r.type != 11:
                if ports_done.has_key(trace_id):
                    continue
                ports_done[trace_id] = None
            trace[s.ttl] = r.src
            rt[trace_id] = trace

        trt = {}
        for trace_id in rt:
            trace = rt[trace_id]
            loctrace = []
            for i in range(max(trace.keys())):
                ip = trace.get(i,None)
                if ip is None:
                    continue
                loc = locate_ip(ip)
                if loc is None:
                    continue
#                loctrace.append((ip,loc)) # no labels yet
                loctrace.append(loc)
            if loctrace:
                trt[trace_id] = loctrace

        tr = map(lambda x: Gnuplot.Data(x,with_="lines"), trt.values())
        g = Gnuplot.Gnuplot()
        world = Gnuplot.File(conf.gnuplot_world,with_="lines")
        g.plot(world,*tr)
        return g

    def make_graph(self,ASres=None,padding=0):
        if ASres is None:
            ASres = conf.AS_resolver
        self.graphASres = ASres
        self.graphpadding = padding
        ips = {}
        rt = {}
        ports = {}
        ports_done = {}
        for s,r in self.res:
            r = r[IP] or r[IPv6] or r
            s = s[IP] or s[IPv6] or s
            ips[r.src] = None
            if TCP in s:
                trace_id = (s.src,s.dst,6,s.dport)
            elif UDP in s:
                trace_id = (s.src,s.dst,17,s.dport)
            elif ICMP in s:
                trace_id = (s.src,s.dst,1,s.type)
            else:
                trace_id = (s.src,s.dst,s.proto,0)
            trace = rt.get(trace_id,{})
            ttl = IPv6 in s and s.hlim or s.ttl
            if not (ICMP in r and r[ICMP].type == 11) and not (IPv6 in r and ICMPv6TimeExceeded in r):
                if trace_id in ports_done:
                    continue
                ports_done[trace_id] = None
                p = ports.get(r.src,[])
                if TCP in r:
                    p.append(r.sprintf("<T%ir,TCP.sport%> %TCP.sport% %TCP.flags%"))
                    trace[ttl] = r.sprintf('"%r,src%":T%ir,TCP.sport%')
                elif UDP in r:
                    p.append(r.sprintf("<U%ir,UDP.sport%> %UDP.sport%"))
                    trace[ttl] = r.sprintf('"%r,src%":U%ir,UDP.sport%')
                elif ICMP in r:
                    p.append(r.sprintf("<I%ir,ICMP.type%> ICMP %ICMP.type%"))
                    trace[ttl] = r.sprintf('"%r,src%":I%ir,ICMP.type%')
                else:
                    p.append(r.sprintf("{IP:<P%ir,proto%> IP %proto%}{IPv6:<P%ir,nh%> IPv6 %nh%}"))
                    trace[ttl] = r.sprintf('"%r,src%":{IP:P%ir,proto%}{IPv6:P%ir,nh%}')
                ports[r.src] = p
            else:
                trace[ttl] = r.sprintf('"%r,src%"')
            rt[trace_id] = trace
    
        # Fill holes with unk%i nodes
        unknown_label = incremental_label("unk%i")
        blackholes = []
        bhip = {}
        for rtk in rt:
            trace = rt[rtk]
            k = trace.keys()
            for n in range(min(k), max(k)):
                if not trace.has_key(n):
                    trace[n] = unknown_label.next()
            if not ports_done.has_key(rtk):
                if rtk[2] == 1: #ICMP
                    bh = "%s %i/icmp" % (rtk[1],rtk[3])
                elif rtk[2] == 6: #TCP
                    bh = "%s %i/tcp" % (rtk[1],rtk[3])
                elif rtk[2] == 17: #UDP                    
                    bh = '%s %i/udp' % (rtk[1],rtk[3])
                else:
                    bh = '%s %i/proto' % (rtk[1],rtk[2]) 
                ips[bh] = None
                bhip[rtk[1]] = bh
                bh = '"%s"' % bh
                trace[max(k)+1] = bh
                blackholes.append(bh)
    
        # Find AS numbers
        ASN_query_list = dict.fromkeys(map(lambda x:x.rsplit(" ",1)[0],ips)).keys()
        if ASres is None:            
            ASNlist = []
        else:
            ASNlist = ASres.resolve(*ASN_query_list)            
    
        ASNs = {}
        ASDs = {}
        for ip,asn,desc, in ASNlist:
            if asn is None:
                continue
            iplist = ASNs.get(asn,[])
            if ip in bhip:
                if ip in ports:
                    iplist.append(ip)
                iplist.append(bhip[ip])
            else:
                iplist.append(ip)
            ASNs[asn] = iplist
            ASDs[asn] = desc
    
    
        backcolorlist=colgen("60","86","ba","ff")
        forecolorlist=colgen("a0","70","40","20")
    
        s = "digraph trace {\n"
    
        s += "\n\tnode [shape=ellipse,color=black,style=solid];\n\n"
    
        s += "\n#ASN clustering\n"
        for asn in ASNs:
            s += '\tsubgraph cluster_%s {\n' % asn
            col = backcolorlist.next()
            s += '\t\tcolor="#%s%s%s";' % col
            s += '\t\tnode [fillcolor="#%s%s%s",style=filled];' % col
            s += '\t\tfontsize = 10;'
            s += '\t\tlabel = "%s\\n[%s]"\n' % (asn,ASDs[asn])
            for ip in ASNs[asn]:
    
                s += '\t\t"%s";\n'%ip
            s += "\t}\n"
    
    
    
    
        s += "#endpoints\n"
        for p in ports:
            s += '\t"%s" [shape=record,color=black,fillcolor=green,style=filled,label="%s|%s"];\n' % (p,p,"|".join(ports[p]))
    
        s += "\n#Blackholes\n"
        for bh in blackholes:
            s += '\t%s [shape=octagon,color=black,fillcolor=red,style=filled];\n' % bh

        if padding:
            s += "\n#Padding\n"
            pad={}
            for snd,rcv in self.res:
                if rcv.src not in ports and rcv.haslayer(Padding):
                    p = rcv.getlayer(Padding).load
                    if p != "\x00"*len(p):
                        pad[rcv.src]=None
            for rcv in pad:
                s += '\t"%s" [shape=triangle,color=black,fillcolor=red,style=filled];\n' % rcv
    
    
            
        s += "\n\tnode [shape=ellipse,color=black,style=solid];\n\n"
    
    
        for rtk in rt:
            s += "#---[%s\n" % `rtk`
            s += '\t\tedge [color="#%s%s%s"];\n' % forecolorlist.next()
            trace = rt[rtk]
            k = trace.keys()
            for n in range(min(k), max(k)):
                s += '\t%s ->\n' % trace[n]
            s += '\t%s;\n' % trace[max(k)]
    
        s += "}\n";
        self.graphdef = s
    
    def graph(self, ASres=None, padding=0, **kargs):
        """x.graph(ASres=conf.AS_resolver, other args):
        ASres=None          : no AS resolver => no clustering
        ASres=AS_resolver() : default whois AS resolver (riswhois.ripe.net)
        ASres=AS_resolver_cymru(): use whois.cymru.com whois database
        ASres=AS_resolver(server="whois.ra.net")
        type: output type (svg, ps, gif, jpg, etc.), passed to dot's "-T" option
        target: filename or redirect. Defaults pipe to Imagemagick's display program
        prog: which graphviz program to use"""
        if ASres is None:
            ASres = conf.AS_resolver
        if (self.graphdef is None or
            self.graphASres != ASres or
            self.graphpadding != padding):
            self.make_graph(ASres,padding)

        return do_graph(self.graphdef, **kargs)



    
def traceroute(target, dport=80, minttl=1, maxttl=30, sport=RandShort(), l4 = None, filter=None, timeout=2, verbose=None, **kargs):
    """Instant TCP traceroute
traceroute(target, [maxttl=30,] [dport=80,] [sport=80,] [verbose=conf.verb]) -> None
"""
    if verbose is None:
        verbose = conf.verb
    if filter is None:
        # we only consider ICMP error packets and TCP packets with at
        # least the ACK flag set *and* either the SYN or the RST flag
        # set
        filter="(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12)) or (tcp and (tcp[13] & 0x16 > 0x10))"
    if l4 is None:
        a,b = sr(IP(dst=target, id=RandShort(), ttl=(minttl,maxttl))/TCP(seq=RandInt(),sport=sport, dport=dport),
                 timeout=timeout, filter=filter, verbose=verbose, **kargs)
    else:
        # this should always work
        filter="ip"
        a,b = sr(IP(dst=target, id=RandShort(), ttl=(minttl,maxttl))/l4,
                 timeout=timeout, filter=filter, verbose=verbose, **kargs)

    a = TracerouteResult(a.res)
    if verbose:
        a.show()
    return a,b



#####################
## Reporting stuff ##
#####################

def report_ports(target, ports):
    """portscan a target and output a LaTeX table
report_ports(target, ports) -> string"""
    ans,unans = sr(IP(dst=target)/TCP(dport=ports),timeout=5)
    rep = "\\begin{tabular}{|r|l|l|}\n\\hline\n"
    for s,r in ans:
        if not r.haslayer(ICMP):
            if r.payload.flags == 0x12:
                rep += r.sprintf("%TCP.sport% & open & SA \\\\\n")
    rep += "\\hline\n"
    for s,r in ans:
        if r.haslayer(ICMP):
            rep += r.sprintf("%TCPerror.dport% & closed & ICMP type %ICMP.type%/%ICMP.code% from %IP.src% \\\\\n")
        elif r.payload.flags != 0x12:
            rep += r.sprintf("%TCP.sport% & closed & TCP %TCP.flags% \\\\\n")
    rep += "\\hline\n"
    for i in unans:
        rep += i.sprintf("%TCP.dport% & ? & unanswered \\\\\n")
    rep += "\\hline\n\\end{tabular}\n"
    return rep



def IPID_count(lst, funcID=lambda x:x[1].id, funcpres=lambda x:x[1].summary()):
    idlst = map(funcID, lst)
    idlst.sort()
    classes = [idlst[0]]+map(lambda x:x[1],filter(lambda (x,y): abs(x-y)>50, map(lambda x,y: (x,y),idlst[:-1], idlst[1:])))
    lst = map(lambda x:(funcID(x), funcpres(x)), lst)
    lst.sort()
    print "Probably %i classes:" % len(classes), classes
    for id,pr in lst:
        print "%5i" % id, pr
    
    
def fragleak(target,sport=123, dport=123, timeout=0.2, onlyasc=0):
    load = "XXXXYYYYYYYYYY"
#    getmacbyip(target)
#    pkt = IP(dst=target, id=RandShort(), options="\x22"*40)/UDP()/load
    pkt = IP(dst=target, id=RandShort(), options="\x00"*40, flags=1)/UDP(sport=sport, dport=sport)/load
    s=conf.L3socket()
    intr=0
    found={}
    try:
        while 1:
            try:
                if not intr:
                    s.send(pkt)
                sin,sout,serr = select([s],[],[],timeout)
                if not sin:
                    continue
                ans=s.recv(1600)
                if not isinstance(ans, IP): #TODO: IPv6
                    continue
                if not isinstance(ans.payload, ICMP):
                    continue
                if not isinstance(ans.payload.payload, IPerror):
                    continue
                if ans.payload.payload.dst != target:
                    continue
                if ans.src  != target:
                    print "leak from", ans.src,


#                print repr(ans)
                if not ans.haslayer(Padding):
                    continue

                
#                print repr(ans.payload.payload.payload.payload)
                
#                if not isinstance(ans.payload.payload.payload.payload, Raw):
#                    continue
#                leak = ans.payload.payload.payload.payload.load[len(load):]
                leak = ans.getlayer(Padding).load
                if leak not in found:
                    found[leak]=None
                    linehexdump(leak, onlyasc=onlyasc)
            except KeyboardInterrupt:
                if intr:
                    raise
                intr=1
    except KeyboardInterrupt:
        pass

def fragleak2(target, timeout=0.4, onlyasc=0):
    found={}
    try:
        while 1:
            p = sr1(IP(dst=target, options="\x00"*40, proto=200)/"XXXXYYYYYYYYYYYY",timeout=timeout,verbose=0)
            if not p:
                continue
            if Padding in p:
                leak  = p[Padding].load
                if leak not in found:
                    found[leak]=None
                    linehexdump(leak,onlyasc=onlyasc)
    except:
        pass
    

conf.stats_classic_protocols += [TCP,UDP,ICMP]
conf.stats_dot11_protocols += [TCP,UDP,ICMP]
