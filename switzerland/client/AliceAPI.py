#!/usr/bin/env python

import time
from switzerland.client.Alice import Alice
from switzerland.client.AliceConfig import AliceConfig,alice_options

def connectServer(config):
    return xAlice(config)

class ConfigError(Exception):
    pass
    
class ClientConfig:
    def __init__(self):
        self.actual_config = AliceConfig()
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

class xAlice:
    def __init__(self, config):
        assert isinstance(config, ClientConfig)
        config.in_use = True
        self.config = config
        self.actual_alice = Alice(config.actual_config)
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
        return []

 
class xPeer:
    def __init__(self, actual_peer):
        self.actual_peer = actual_peer
    def traceroute(self):
        return ""
    def active_flows(self):
        return []
    def old_flows(self):
        return []


class xFlow:
    def __init__(self, actual_flow):
        self.actual_flow = actual_flow
        self.flow_tuple = self.actual_flow.summary()[2]

    def get_pair(self):
        """
        Return the matching flow in the other direction, or None if there
        isn't one.
        """
        return None

    def is_active(self):
        return True
    
    def get_new_packet_count(self):
        return 0

    def get_new_byte_count(self):
        return 0

    def get_new_dropped(self):
        return 0

    def get_new_injected(self):
        return 0
 
    def get_new_modified(self):
        return 0

class xPacket:
    def __init__(self):
        pass

