from scapy.all import *
import logging
logger = logging.getLogger('app.'+__name__)

"""
=== Run information ===

Scheme:       weka.classifiers.trees.J48 -C 0.25 -M 2
Relation:     out-weka.filters.unsupervised.attribute.RemoveUseless-M23.0-weka.filters.unsupervised.attribute.Remove-V-R53,171,76,75,80,167,145,170,172,174,154,147,132,152,169,79,155-156,135,144,151,146,82,81,91-92,74,70,78,73,149,153,150,175,179,142,139,72,71,177,93,140,176,178,96,94-95,90,84,86,85,87,21,20,22,12,14,13,15,89,10,148,11,83,88,19,168,141,180,114,166,110,115,111,113,112,68,1,52,116,121,181-weka.filters.unsupervised.attribute.Remove-V-R1-5,7,6,8-13,15,14,16-26,82-weka.filters.unsupervised.attribute.Remove-R3,7,12,15,21,24
Instances:    117621
Attributes:   21
              eth.eth.type
              tcp.tcp.stream
              ip.ip.flags
              ip.ip.proto
              tcp.tcp.dstport
              tcp.tcp.srcport
              tcp.tcp.window_size
              tcp.tcp.window_size_value
              tcp.tcp.hdr_len
              tcp.tcp.ack
              tcp.tcp.seq
              ip.ip.len
              tcp.tcp.len
              tcp.tcp.nxtseq
              tcp.tcp.analysis.tcp.analysis.bytes_in_flight
              tcp.tcp.analysis.tcp.analysis.push_bytes_sent
              tcp.tcp.flags
              ip.ip.src_host
              ipv6.ipv6.nxt
              ipv6.ipv6.plen
              class
Test mode:    evaluate on training data

=== Classifier model (full training set) ===

J48 pruned tree
------------------

eth.eth.type = 0x000086dd
|   ipv6.ipv6.plen <= 1032
|   |   ipv6.ipv6.plen <= 325: normal (197.0)
|   |   ipv6.ipv6.plen > 325: udp6_flood (10000.0)
|   ipv6.ipv6.plen > 1032: tcp6_flood (10000.0)
eth.eth.type = 0x00000800
|   ip.ip.flags = 0x00000002: normal (77307.0)
|   ip.ip.flags = 0x00000000
|   |   ip.ip.len <= 1052
|   |   |   ip.ip.len <= 689: normal (67.0)
|   |   |   ip.ip.len > 689: udp4_flood (10000.0)
|   |   ip.ip.len > 1052: tcp4_flood (10000.0)
eth.eth.type = 0x00000806: normal (44.0)
eth.eth.type = 0x0000888e: normal (6.0)

Number of Leaves  : 	9

Size of the tree : 	15


Time taken to build model: 2.43 seconds

=== Evaluation on training set ===

Time taken to test model on training data: 0.29 seconds

=== Summary ===

Correctly Classified Instances      117621              100      %
Incorrectly Classified Instances         0                0      %
Kappa statistic                          1
Mean absolute error                      0
Root mean squared error                  0
Relative absolute error                  0      %
Root relative squared error              0      %
Total Number of Instances           117621

=== Detailed Accuracy By Class ===

                 TP Rate  FP Rate  Precision  Recall   F-Measure  MCC      ROC Area  PRC Area  Class
                 1.000    0.000    1.000      1.000    1.000      1.000    1.000     1.000     normal
                 1.000    0.000    1.000      1.000    1.000      1.000    1.000     1.000     tcp4_flood
                 1.000    0.000    1.000      1.000    1.000      1.000    1.000     1.000     tcp6_flood
                 1.000    0.000    1.000      1.000    1.000      1.000    1.000     1.000     udp4_flood
                 1.000    0.000    1.000      1.000    1.000      1.000    1.000     1.000     udp6_flood
Weighted Avg.    1.000    0.000    1.000      1.000    1.000      1.000    1.000     1.000

=== Confusion Matrix ===

     a     b     c     d     e   <-- classified as
 77621     0     0     0     0 |     a = normal
     0 10000     0     0     0 |     b = tcp4_flood
     0     0 10000     0     0 |     c = tcp6_flood
     0     0     0 10000     0 |     d = udp4_flood
     0     0     0     0 10000 |     e = udp6_flood
"""

class PacketType(object):
    def __init__(self,n):
        self._name = n
        self._count = 0
    def add(self):
        self._count += 1
        return self
    def count(self):
        return self._count
    def __pos__(self):
        return self.add()
    def __str__(self):
        return self._name
    def __int__(self):
        return self._count

PACKET_LIST = {
  'NORMAL'   :PacketType('NORMAL'),
  'MALICIOUS':{
    'TCP4'      :PacketType('TCP4 FLOOD'),
    'TCP6'      :PacketType('TCP6 FLOOD'),
    'UDP4'      :PacketType('UDP4 FLOOD'),
    'UDP6'      :PacketType('UDP6 FLOOD'),
    'UNDETECTED':PacketType('UNDETECTED')
  }
}

def detect(pkt, blocker=None, unblocker=None, output=None):
    global PACKET_LIST
    detected = PACKET_LIST['MALICIOUS']['UNDETECTED']

    if pkt[Ether].type==int(b'0x800'):
        #IPv4
        ip = pkt[IP].src
    elif pkt[Ether].type==int(b'0x86DD'):
        #IPv6
        ip = pkt[IPv6].src

    if getattr(pkt[Ether], 'type') == int(b'0x000086dd',16):
        if getattr(pkt[IPv6], 'plen') <= 1032:
            if getattr(pkt[IPv6], 'plen') <= 325:
                detected = +PACKET_LIST['NORMAL']
            elif getattr(pkt[IPv6], 'plen') > 325:
                detected = +PACKET_LIST['MALICIOUS']['UDP6']
                logger.warning(detected)
        elif getattr(pkt[IPv6], 'plen') > 1032:
            detected = +PACKET_LIST['MALICIOUS']['TCP6']
            logger.warning(detected)
    elif getattr(pkt[Ether], 'type') == int(b'0x00000800',16):
        if getattr(pkt[IP], 'flags') == int('0x00000002',16):
            detected = +PACKET_LIST['NORMAL']
        elif getattr(pkt[IP], 'flags') == int('0x00000000',16):
            if getattr(pkt[IP], 'len') <= 1052:
                if getattr(pkt[IP], 'len') <= 1052:
                    detected = +PACKET_LIST['NORMAL']
                elif getattr(pkt[IP], 'len') <= 1052:
                    detected = +PACKET_LIST['MALICIOUS']['UDP4']
                    logger.warning(detected)
            elif getattr(pkt[IP], 'len') > 1052:
                detected = +PACKET_LIST['MALICIOUS']['TCP4']
                logger.warning(detected)
    elif getattr(pkt[Ether], 'type') == int(b'0x00000806',16):
        detected = +PACKET_LIST['NORMAL']
    elif getattr(pkt[Ether], 'type') == int(b'0x0000888e',16):
        detected = +PACKET_LIST['NORMAL']

    if detected != PACKET_LIST['NORMAL']:
        if detected == PACKET_LIST['MALICIOUS']['UNDETECTED']:
            +PACKET_LIST['MALICIOUS']['UNDETECTED']
            logger.warning(detected)
        else:
            blocker(ip)
    return PACKET_LIST
