from scapy.all import *
from threading import Thread
import logging

__logger = logging.getLogger('app.'+__name__)

def capture(iface, packethandler=None):
    # conf.L3socket=L3dnetSocket
    # conf.L3listen=L3pcapListenSocket
    # conf.L3socket(iface=iface)
    _sniffer =  sniffer(iface, packethandler)
    print(_sniffer.summary())
    return _sniffer


class sniffer(Thread):
    def __init__(self, iface, packethandler=None):
        Thread.__init__(self,daemon=True)
        self.packethandler = packethandler
        self.iface = iface
    def run(self):
        self._sniff =sniff(iface=self.iface, prn=self.packethandler)

# def dissect(pkt, *args):
#     value = None
#     for attribute in args:
#         try:
#             if value == None:
#                 value = getattr(pkt, attribute)
#             else:
#                 value = getattr(value, attribute)
#         except TypeError:
#             __logger.debug('Cannot get %s from packet %s', attribute, pkt)
#     return value
