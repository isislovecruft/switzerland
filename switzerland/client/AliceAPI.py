#!/usr/bin/env python

import time
from switzerland.client.Alice import Alice
from switzerland.client.Packet import Packet
from switzerland.client.AliceConfig import AliceConfig,alice_options


# XXX none of this does any locking at the moment.
# That's probably okay because of the Global Interpreter Lock and
# because nothing the UI does currently changes the client's state in
# any complicated way.  But if either of those things change, the API
# will need to be made threadsafe.

def connectServer(config):
    return xAlice(config)

class ConfigError(Exception):
    pass

class ClientStopped(Exception):
    """
    This exception is raised if the client crashes or disconnects, if the
    server dies, etc.  It will be raised with a two element data tuple
    (summary, details)
    
    summary - a brief explanation of the disconnection event that all users
              should be able to understand

    details - a traceback showing a real underlying exception (if any)
              and details of the disconnection event
    """
    pass

class ClientConfig:
    def __init__(self):
        self.actual_config = AliceConfig(getopt=True)
        self.extract_options_for_api()
        self.in_use = False # this AliceConfig instance is in use by a client
                            # that's connected to a server

    def tweakable_options(self):
        return self.tweakable

    def immutable_options(self):
        return self.immutable

    def extract_options_for_api(self):
        """
        AliceAPI will feed these to code that may want to know about options
        it can change
        """
        self.tweakable = []
        self.immutable = []
        for opt, info in alice_options.items():
            default, type, mutable, visible = info
            if visible:
                if mutable:
                    self.tweakable.append((opt,type))
                else:
                    self.immutable.append((opt,type))

    def set_option(self, option, value):
        try:
            default, type, mutable, visible = alice_options[option]
        except:
            raise KeyError, '"%s" is not a valid option name' % option

        if not visible:
            raise ConfigError, "trying to set a hidden option"

        if self.in_use and not mutable:
            raise ConfigError, "Trying to set an immutable variable for a running client"

        # XXX check the type here
        self.actual_config.__dict__[option] = value

    def get_option(self, option):
        if option not in alice_options:
            raise KeyError, '"%s" is not a valid option name' % option
        return self.actual_config.__dict__[option]


tr = None # a Tracerouter, to be shared with Alice

class xAlice:
    def __init__(self, config):
        assert isinstance(config, ClientConfig)
        config.in_use = True
        self.config = config

        # begin XXX This is supposed to be "equivalent" to Alice.main;
        # work out what that means and unify the two!
        self.actual_alice = Alice(config.actual_config)
        self.actual_alice.listener.start()
        self.actual_alice.start()
        # end XXX

        global tr
        tr = self.actual_alice.tr
        self.sinfo = {}
        self.cinfo = {}
        link = self.actual_alice.link
        self.sinfo["server"]=link.peer[0]
        self.sinfo["ip"]=link.server_ip

    def disconnect(self):
        pass # XXX

    def get_server_info(self):
        link = self.actual_alice.link
        self.sinfo["connection time"] = time.time() - link.time_connected
        self.sinfo["message count"  ] = (link.messages_out, link.messages_in)
        self.sinfo["last message"   ] = time.time() - link.last_sent
        return self.sinfo

    def get_client_info(self):
        link = self.actual_alice.link

        # This is not "efficient" but, like, whatever:
        if "public_ip" in link.__dict__:
            self.cinfo["public ip"] = link.public_ip
        else:
            self.cinfo["public ip"] = None

        self.cinfo["network interface"] = self.actual_alice.config.interface
        self.cinfo["ntp method"] = self.actual_alice.time_manager.method
        self.cinfo["clock dispersion"] = self.actual_alice.root_dispersion
        return self.cinfo

    def get_peers(self):
        peers = self.actual_alice.fm.peers.items()
        return [xPeer(p, self.actual_alice.fm) for p in peers]

 
class xPeer:
    def __init__(self, ip_and_actual_peer, flow_manager):
        self.ip, self.actual_peer = ip_and_actual_peer
        self.fm=flow_manager
    def traceroute(self):
        if tr:
            return tr.route_to(self.ip)
        else:
            return None
    def firewalled(self):
        return self.actual_peer.firewalled

    def new_flows(self):
        self.fm.lock.acquire()
        try:
            xflows =  map(xFlow, self.fm.api_new_flows)
            self.fm.api_new_flows = []
            return xflows
        finally:
            self.fm.lock.release()
        
class xFlow:
    def __init__(self, actual_flow):
        self.actual_flow = actual_flow
        self.flow_tuple = self.actual_flow.summary()[2]
        self.reported_packets = 0
        self.reported_bytes = 0

    def get_id(self):
        return self.actual_flow.id
    
    def get_pair(self):
        """
        Return the matching flow in the other direction, or None if there
        isn't one.
        """
        return None

    def is_active(self):
        return self.actual_flow.active
    
    def get_new_packet_count(self):
        n = self.actual_flow.packets_transferred - self.reported_packets
        print "Getting packet count", n
        self.reported_packets = self.actual_flow.packets_transferred
        return n

    def get_new_byte_count(self):
        n = self.actual_flow.bytes_transferred - self.reported_bytes
        self.reported_bytes = self.actual_flow.bytes_transferred
        return n

    def get_new_dropped_packets(self):
        return []

    def get_new_injected_packets(self):
        return []
 
    def get_new_modified_packets(self):
        return []

class xPacket:
    def __init__(self, actual_packet):
        assert isinstance(actual_packet, Packet)
        self.actual_packet = actual_packet
    
    def raw_data(self):
        return self.actual_packet.original_data
    
    def get_summary_string(self):
        return "Here is some packet info."

    def timestamp(self):
        pass
    
    def get_summary_fields(self):
        ret_fields = dict()
        ret_fields['ip_id'] = ''
        ret_fields['tcp_flags'] = ''
        ret_fields['tcp_seqno'] = ''
        ret_fields['payload_size'] = ''
        return ret_fields
        
    def get_details(self):
        pass
    
