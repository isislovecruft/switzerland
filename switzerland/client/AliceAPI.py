
from switzerland.client.Alice import Alice
from switzerland.client.AliceConfig import AliceConfig

class xAliceConfig:
    def __init__(self):
        pass

class xAlice:
    def __init__(self, config):
        pass
 
class xPeer:
    def __init__(self):
        pass

class xFlow:
    def __init__(self):
        pass
     

class AliceAPI:
    """
    Interface to Alice to protect GUIs from internal changes
    to Alice.
    """
    def __init__(self, alice):
        self.alice = alice

    def AliceConfig(self):
        "A factory function for AliceConfig objects".
        return xAliceConfig()
    
    def connectServer(self, config):
        return xAlice(config)
    
    def disconnectServer(self):
        pass
    
    def getServerInfo(self, serverId):
        pass
    
    def getClientInfo(self, clientId):
        pass
    
    def getPeers(self):
        pass

    def getPacketInfo(self, packetId):
        pass
