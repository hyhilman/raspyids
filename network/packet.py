from scapy.all import *
import logging

__logger = logging.getLogger('app.'+__name__)

def capture(iface, callback=None):
    # conf.L3socket=L3dnetSocket
    # conf.L3listen=L3pcapListenSocket
    # conf.L3socket(iface=iface)
    return sniff(iface=iface, prn=callback)
# 
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
