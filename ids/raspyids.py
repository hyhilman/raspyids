from output import logger
from network import firewall
from network.firewall import __protocols
from detectionengine import j48
from network import packet
from scapy.all import *

class PythonRaspberryIds:

    def block(self, ip, protocol=None):
        firewall.block(ip, protocol)

    def unblock(self):
        firewall.unblock(ip, protocol)

    def showrule(self, ip=None):
        firewall.show(ip)

    def capture(self, iface):
        packet.capture(iface, self.detect)

    def detect(self, pkt):
        j48.detect(pkt, blocker=self.block, unblocker=self.unblock)

    def output(self): pass

def main():
    logger.init()
    ids = PythonRaspberryIds()
    ids.capture('wlp3s0')

if __name__ == '__main__':
    main()
