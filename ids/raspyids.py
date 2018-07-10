from .output import logger
from .network import firewall
from .network import packet
from .engine import decision
from scapy.all import *
import logging
import traceback

class PythonRaspberryIds:
    def __init__(self):
        self.packet_summary = {}

    def block(self, ip, protocol=None):
        firewall.block(ip, protocol)

    def unblock(self):
        firewall.unblock(ip, protocol)

    def showrule(self, ip=None):
        firewall.show(ip)

    def capture(self, iface=None):
        self._sniffer,self.scapy = packet.capture(iface, self.detect)
        while self._sniffer.isAlive():
            self._sniffer.join(5)
        raise SystemExit('Shuting down sniffer thread!')

    def detect(self, pkt):
        self.packet_summary = decision.detect(pkt, blocker=self.block, unblocker=self.unblock)

    def output(self): pass

    def summary(self, packet_summary=None):
        output = ''
        if packet_summary == None:
            packet_summary=self.packet_summary
        for _,val in packet_summary.items():
            if type(val) != decision.PacketType:
                if type(val) != dict:
                    raise ValueError('Invalid summary value')
                else:
                    output += self.summary(val)
            else:
                output += '\n\tDetected %i %s packets' % (val,val)
        return output

def main():
    #init global logger config
    logger.init()
    ids = PythonRaspberryIds()
    try:
        ids.capture('eth1')
    except (KeyboardInterrupt,SystemExit):
        # init local logger for this file script
        ids.scapy.show_summary()
        logging.getLogger('app.'+__name__).critical('Program stopped manually! \nSummary of packets %s' % ids.summary())
        sys.exit(0)

if __name__ == '__main__':
    main()
