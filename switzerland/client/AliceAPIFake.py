
import time
import random
import logging

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
        return self.tweakable_options

    def immutable_options(self):
        return self.immutable_options

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
                 
        tweakable = self.tweakable_options = [("log_level", int),
        ("seriousness", int),
        ("do_cleaning", bool)]
        immutable = self.immutable_options = [("host", ip),
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
        #self.fake_peers.append(xPeer(None))
        #self.fake_peers[0].fake_flows.append(xFlow(None))
        #self.fake_peers[0].fake_flows.append(xFlow(None))
        #self.fake_peers.append(xPeer(None))
        #self.fake_peers[1].fake_flows.append(xFlow(None))
        #self.fake_peers[1].fake_flows.append(xFlow(None))
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


class xFlow:
    def __init__(self, actual_flow):
        self.actual_flow = actual_flow
        #self.flow_tuple = self.actual_flow.summary()[3]
        self.flow_tuple = ( \
            str(random.randint(1,255)) + '.' + str(random.randint(1,255)) + '.' + str(random.randint(1,255)) + '.' + str(random.randint(1,255)), 
            random.randint(1025,65000), 
            str(random.randint(1,255)) + '.' + str(random.randint(1,255)) + '.' + str(random.randint(1,255)) + '.' + str(random.randint(1,255)), 
            random.randint(1025,65000), 
            random.choice(('tcp','ip')))
        self.last_update = time.time()
        self.last_packet_count_time = time.time()
        self.last_byte_count_time = time.time()
        self.last_dropped_time = time.time()
        self.last_injected_time = time.time()
        self.last_modified_time = time.time()

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
        return (random.randint(10,20) * diff)
        

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
        pass

