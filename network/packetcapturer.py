from scapy.all import *

def init(iface, callback=None):
    # conf.L3socket=L3dnetSocket
    # conf.L3listen=L3pcapListenSocket
    # conf.L3socket(iface=iface)
    return sniff(iface=iface, prn=callback)

# class PacketCapturer:
#     # _indent = 0
#     def __init__(self, iface, callback=None):
#         # conf.L3socket=L3dnetSocket
#         # conf.L3listen=L3pcapListenSocket
#         conf.L3socket(iface=iface)
#         self._capturer = sniff(iface=iface, prn=callback1)

    # def dissect(self, *args):
    #     value = None
    #     for i in args:
    #         if value == None:
    #             value = getattr(self._capturer, i)
    #         else:
    #             value = getattr(value, i)
    #     return value;
    # def getPacket(self, indent=None):
    #     if indent==None:
    #         return self._capturer[self._indent]
    #     else:
    #         return self._capturer[indent]
    #
    # def nextPacket(self):
    #     self._indent = self._indent + 1
    #     return self
    #
    # def previousPacket(self):
    #     if self._indent - 1 < 0:
    #         raise Exception("Minimum packet indent is 0"):
    #     self._indent = self._indent - 1
    #     return self
