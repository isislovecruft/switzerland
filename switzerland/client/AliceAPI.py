
from switzerland.client.Alice import Alice
from switzerland.client.AliceConfig import AliceConfig

def ClientConfig(self):
    "A factory function for the API's xAliceConfig objects".
    return xAliceConfig()

def connectServer(self, config):
    return xAlice(config)
    
class xAliceConfig:
    def __init__(self):
        self.actual_config = AliceConfig()
    def tweakable_options(self):
        return []
    def immutable_options(self):
        return []
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

