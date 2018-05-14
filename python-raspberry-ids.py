from output import logger
from network import firewall
from engine import j48
from network import packet

class PythonRaspberryIds:

    def block(self, ip, protocol=None):
        if protocol in firewall.__protocols or protocol == None:
            firewall.block(ip, protocol)
        else:
            logger.warn('Protocol %s not in list [%s]', protocol, firewall.__protocols)

    def unblock(self):
        firewall.unblock(ip, protocol)

    def showrule(self, ip=None):
        if ip in firewall.__ip or ip == None:
            firewall.show(ip)
        else:
            logger.warn('IP %s is not in list [%s]', ip, firewall.__ip)

    def capture(self, iface):
        packet.capture(iface, self.detect)

    def detect(self, pkt):
        j48.detect(pkt, blocker=self.block, unblocker=self.unblock)

    def output(self): pass

from scapy.all import *
def main():
    logger.init()
    ids = PythonRaspberryIds()
    sniff(offline="udp_ip6_flood.pcap", prn=ids.detect)

if __name__ == '__main__':
    main()
