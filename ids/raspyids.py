from scapy.all import *
from .output import logger
from .network import firewall
from .network import packet
from .engine import decision
import atexit
import logging
import traceback

class PythonRaspberryIds:
    def __init__(self):
        self.output()
        self.packet_summary = {}

    def block(self, ip, protocol=None):
        firewall.block(ip, protocol)

    def unblock(self, ip=None):
        firewall.unblock(ip)

    def showrule(self, ip=None):
        firewall.show(ip)

    def capture(self, iface=None):
        logging.getLogger('app.'+__name__).info('listening on interface :%s' % iface)
        self._sniffer = packet.capture(iface, self.detect)
        while self._sniffer.isAlive():
            self._sniffer.join(5)

    def detect(self, pkt):
        #print('Recive new packet', pkt.summary())
        self.packet_summary = decision.detect(pkt, blocker=self.block, unblocker=self.unblock)

    def output(self):
        logger.init()

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

    def exit(self):
        logging.getLogger('app.'+__name__).critical('Program stopped manually! \nSummary of packets %s' % self.summary())
        logging.getLogger('app.'+__name__).info('Show firewall rules created since IDS on')
        logging.getLogger('app.'+__name__).info(self.showrule())
        self.unblock()
        logging.getLogger('app.'+__name__).info('flush firewall rules')

def main():
    _p = argparse.ArgumentParser()
    _p.add_argument("-i", "--iface", help="interface")
    args = _p.parse_args()

    ids = PythonRaspberryIds()
    atexit.register(ids.exit)
    try:
        ids.capture(args.iface)
    except (KeyboardInterrupt,SystemExit):
        sys.exit(0)

if __name__ == '__main__':
    main()
