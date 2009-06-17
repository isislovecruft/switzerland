
from switzerland.client.Alice import Alice
from switzerland.client.AliceConfig import AliceConfig

class AliceAPI:
    """
    Interface to Alice to protect GUIs from internal changes
    to Alice.
    """
    def __init__(self, alice):
        self.alice = alice

    def AliceConfig(self):
        return self.alice.config
    
    def Alice(self):
        return self.alice
    
    def connectServer(self):
        pass
    
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
