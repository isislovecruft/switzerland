
import time
import random
import logging
import socket as s
import binascii
import pickle
import types

from switzerland.common.util import bin2int
from switzerland.common import util
rdpcap_available = True

try:
    from scapy import rdpcap
except:
    rdpcap_availabe = False
    
try:
    from scapy import Ether
except:
    from switzerland.lib.shrunk_scapy.layers.l2 import Ether

def ClientConfig(self):
    '''A factory function for the API's ClientConfig objects.'''
    return ClientConfig()

def connectServer(self, config):
    return xAlice(config)
    
class ClientConfig:
    def __init__(self):
        # Fake for no AliceConfig
        self.option_hash = dict()
        #self.actual_config = AliceConfig()
        self.extract_options_for_api()


    def tweakable_options(self):
        return self.tweakable

    def immutable_options(self):
        return self.immutable

    def extract_options_for_api(self):
        # These might turn into functions?
        hostname = "hostname"
        path = "path"
        string = "string"
        ip = "ip"

        """
        AliceAPI will feed these to code that may want to know about options
        it can change
        """
        self.option_hash["host"] = "switzerland.eff.org"
        self.option_hash["port"] = 7778
        self.option_hash["interface"] = None
        self.option_hash["skew"] = 0.0
        self.option_hash["log_level"] = logging.DEBUG
        self.option_hash["seriousness"] = 0
        self.option_hash["do_cleaning"] = True
        self.option_hash["use_ntp"] = True
        self.option_hash["filter_packets"] = True
        self.option_hash["force_public_ip"] = False
        self.option_hash["force_private_ip"] = False
        self.option_hash["packet_buffer_size"] = 25000
        self.option_hash["quiet"] = False         
                 
        self.tweakable = [("log_level", int),
        ("seriousness", int),
        ("do_cleaning", bool)]
        self.immutable = [("host", ip),
        ("port", int),
        ("interface", string),
        ("skew", float),
        ("use_ntp", bool),
        ("filter_packets", bool),
        ("force_public_ip", bool),
        ("force_private_ip", bool),
        ("packet_buffer_size", int),
        ("quiet", bool)]


    def set_option(self,option,value):
        if self.option_hash[option] != None:
            self.option_hash[option] = value
            
        
    def get_option(self,option):
        return self.option_hash.get(option)

class xAlice:
    def __init__(self, config):
        self.start_time = time.time()
        self.message_count = 0
        self.last_message_time = time.time()
        self.fake_peers = list()
        self.fake_peers.append(xPeer(None))
        self.fake_peers[0].fake_flows.append(xFlow(None))
        self.fake_peers[0].fake_flows.append(xFlow(None))
        self.fake_peers.append(xPeer(None))
        self.fake_peers[1].fake_flows.append(xFlow(None))
        self.fake_peers[1].fake_flows.append(xFlow(None))
        #self.fake_peers.append(xPeer(None))
        #self.fake_peers[2].fake_flows.append(xFlow(None))
        #self.fake_peers[2].fake_flows.append(xFlow(None))
        
        assert isinstance(config, ClientConfig)
        #self.actual_alice = Alice(config.actual_config)
        
    def disconnect(self):
        pass
        
    def get_server_info(self):
        temp_time = time.time() - self.start_time
        temp_last = time.time() - self.last_message_time
        info = {'hostname': 'switzerland.eff.org', 
        'ip': '1.2.3.4', 
        'connection time': temp_time, 
        'message_count': self.message_count, 
        'last_message': temp_last}
        return info

    def get_client_info(self):
        info = {'public_ip': '5.6.7.8', 
        'private_ip': '192.168.1.2', 
        'network interface': 'tcp', 
        'ntp method': 'unknown', 
        'clock dispersion': 0.0}
        return info
    
    def get_peers(self):
        return self.fake_peers

 
class xPeer:
    def __init__(self, actual_peer):
        self.actual_peer = actual_peer
        self.fake_flows = list()
        self.firewalled = False
        self.sent_flows = False
        self.ip = s.inet_aton(str(random.randint(1,255)) + '.' + str(random.randint(1,255)) + '.' + str(random.randint(1,255)) + '.' + str(random.randint(1,255)))
   
    def traceroute(self):
        return "Here is the route to this peer"
    def new_flows(self):
        if self.sent_flows:
            return None
        else:
            self.sent_flows = True
            return self.fake_flows
        
    def old_flows(self):
        return []

def int2bin(num):
    #print "num", num, "hex ver", hex(num), hex(num)[2:]
    num = hex(num)[2:]
    if len(num) % 2 == 1:
        num = "0" + num
    #print "trimmed", num
    return binascii.unhexlify(num)

class xFlow:
    def __init__(self, actual_flow):
        self.actual_flow = actual_flow
        #self.flow_tuple = self.actual_flow.summary()[3]
        self.flow_tuple = ( \
            s.inet_aton(str(random.randint(1,255)) + '.' + str(random.randint(1,255)) + '.' + str(random.randint(1,255)) + '.' + str(random.randint(1,255))), 
            int2bin(random.randint(1025,65000)), 
            s.inet_aton(str(random.randint(1,255)) + '.' + str(random.randint(1,255)) + '.' + str(random.randint(1,255)) + '.' + str(random.randint(1,255))), 
            int2bin(random.randint(1025,65000)), 
            int2bin(random.choice((4,6))))
        self.last_update = time.time()
        self.last_packet_count_time = time.time()
        self.last_byte_count_time = time.time()
        self.last_dropped_time = time.time()
        self.last_injected_time = time.time()
        self.last_modified_time = time.time()
        
    def get_id(self):
        return self.actual_flow.id

    def get_pair(self):
        '''Return the matching flow in the other direction, or None if there
        isn\'t one.'''
        return None

    def is_active(self):
        return True
    
    def rand_packet_list(self, starttime, mult=1):
        packets = list()
        tcount = starttime
        tnow = time.time()
        while (tcount < tnow) :
            packets.append((tcount, xPacket()))
            tcount = tcount + random.random() * mult
        return packets
    
    def get_new_packet_count(self):
        diff = time.time() - self.last_packet_count_time
        self.last_packet_count_time = time.time()
        return (int(random.randint(10,20) * diff))
        

    def get_new_byte_count(self):
        return random.randint(10000,50000)

    def get_new_dropped_packets(self):
        packets = self.rand_packet_list(self.last_dropped_time)
        self.last_dropped_time = time.time()
        return packets

    def get_new_injected_packets(self):
        packets = self.rand_packet_list(self.last_injected_time)
        self.last_injected_time = time.time()
        return packets
 
    def get_new_modified_packets(self):
        packets = self.rand_packet_list(self.last_modified_time)
        self.last_modified_time = time.time()
        return packets

class xPacket:
    def __init__(self):
        self.summary_string = str(random.randint(1000000000,9999999999))
        #fileHandle = open('fake_data/' + 'packet1279077254.72')
        #temp_data = pickle.load(fileHandle) 
        temp_data = ["Bogus"]
        if rdpcap_available:
            try:
                temp_data = rdpcap('fake_data/' + 'http.pcap')
            except:
                pass
        self.timestamp = 1279077254.72
        self.actual_packet = Packet(self.timestamp, temp_data[0], None)
    
    def get_summary_string(self):
        return Ether(self.actual_packet.original_data).summary()
    
    def get_ether_info(self):
        if isinstance(self.actual_packet.original_data, Ether) :
            layer = self.actual_packet.original_data
        else:
            layer = Ether(self.actual_packet.original_data)
        result = dict()
        layer_order = list()
        while layer is not None:
            temp_dict = dict()
            layer_order.append(layer.name)
            for key in layer.fields:
                try:
                    value = str(layer.fields[key])
                    temp_dict[key] = value
                except:
                    print "Exception on " + key
                    pass
            result[layer.name] = temp_dict
            if layer.payload is not None and len(layer.payload) > 0:
                layer = layer.payload
            else:
                layer = None
        return (layer_order, result)

    def raw_data(self):
        return self.actual_packet.original_data    
    
    def timestamp(self):
        return self.timestamp
    
    def get_summary_fields(self):
        e = Ether(self.actual_packet.original_data)
        ret_fields = dict()
        ret_fields['ip_id'] = ''
        ret_fields['tcp_flags'] = ''
        ret_fields['tcp_seqno'] = ''
        ret_fields['payload_size'] = ''
        return ret_fields
        
    def get_details(self):
        pass
    
class Packet:
    """Captured user packet (IP datagram)."""

    def __init__(self, timestamp, data, alice, hash=None, has_ll=True):
        """Create a new packet.
        timestamp: when received, seconds since epoch
        data: (string) link layer data
        hash: (string) hash of packet contents
        """
        self.timestamp = timestamp
        self.alice = alice
        self.private_ip = s.inet_aton(str(random.randint(1,255)) + '.' + str(random.randint(1,255)) + '.' + str(random.randint(1,255)) + '.' + str(random.randint(1,255)))
        self.strip_link_layer = has_ll
        self.original_data = data
        self.hash = hash
        self.reported = False
        self._flow_addr = None
        self.key = "XXX frogs"   
