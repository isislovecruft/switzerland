
from switzerland.client.Alice import Alice
from switzerland.client.AliceConfig import AliceConfig,alice_options

def ClientConfig(self):
    "A factory function for the API's xAliceConfig objects".
    return xAliceConfig()

def connectServer(self, config):
    return xAlice(config)
    
class xAliceConfig:
    def __init__(self):
        self.actual_config = AliceConfig()
        self.extract_options_for_api()

    def tweakable_options(self):
        return self.tweakable_options

    def immutable_options(self):
        return self.immutable_options

    def extract_options_for_api(self):
        """
        AliceAPI will feed these to code that may want to know about options
        it can change
        """
        tweakable = self.tweakable_options = []
        immutable = self.immutable_options = []
        for opt, info in alice_options.items():
            default, type, mutable, visible = info
            if visible:
                if mutable:
                    tweakable.append((opt,type))
                else:
                    immutable.append((opt,type))


    def set_option(self,option,value):
        pass

class xAlice:
    def __init__(self, config):
        assert isinstance(config, xAliceConfig)
        self.actual_alice = Alice(config.actual_config)
    def disconnect(self):
        pass
    def get_server_info(self):
        info = {}
        return info
    def get_client_info(self):
        info = {}
        return info
    def get_peers(self):
        return []

 
class xPeer:
    def __init__(self, actual_peer):
        self.actual_peer = actual_peer
    def traceroute(self):
        return ""
    def active_flows(self):
        return []
    def old_flows(self)
        return []


class xFlow:
    def __init__(self, actual_flow):
        self.actual_flow = actual_flow
        self.flow_tuple = self.actual_flow.summary()[3]

    def get_pair(self):
        "Return the matching flow in the other direction, or None if there
        isn't one."
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

class xPacket
    def __init__(self):
        pass

