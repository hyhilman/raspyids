from scapy.all import *
import logging
logger = logging.getLogger('app.'+__name__)

"""
=== Run information ===

Scheme:weka.classifiers.trees.J48 -C 0.25 -M 2
Relation:     out-weka.filters.unsupervised.attribute.Remove-V-R138,137,146,112,145,290,382,148,147,349,346,337,135,143,136,130,162-164,133,132,342,159-160,381,155,161,385,388,387,152-154,158,299,144,384,386,75,65,62,64,63,70,74,66,376,379,377,77,389-weka.filters.unsupervised.attribute.Remove-R6-8,11-12,14-15,17-19,26-27,31,33-36,50-weka.filters.unsupervised.attribute.Remove-R9-weka.filters.unsupervised.attribute.Remove-R8
Instances:    170694
Attributes:   31
              ip.ip.flags_tree.ip.flags.df
              ip.ip.flags
              ip.ip.proto
              eth.eth.type
              ip.ip.len
              ip.ip.src
              tcp.tcp.options_tree.tcp.options.mss_tree.tcp.options.mss_val
              ip.ip.dsfield_tree.ip.dsfield.dscp
              ip.ip.dsfield
              tcp.tcp.hdr_len
              ipv6.ipv6.nxt
              ipv6.ipv6.plen
              tcp.tcp.window_size_value
              udp.udp.length
              udp.udp.stream
              udp.udp.srcport
              ipv6.ipv6.dst
              udp.udp.dstport
              udp.udp.port
              dns.dns.flags_tree.dns.flags.truncated
              dns.dns.count.queries
              dns.dns.count.add_rr
              dns.dns.count.auth_rr
              dns.dns.count.answers
              dns.dns.flags_tree.dns.flags.opcode
              dns.dns.flags_tree.dns.flags.response
              dns.dns.flags
              tcp.tcp.srcport
              tcp.tcp.window_size
              tcp.tcp.stream
              class
Test mode:evaluate on training data

=== Classifier model (full training set) ===

J48 pruned tree
------------------

eth.eth.type = 0x00000800
|   ip.ip.flags_tree.ip.flags.df <= 0
|   |   ip.ip.proto <= 6: flood_tcp4 (100.0)
|   |   ip.ip.proto > 6: flood_udp4 (10000.0)
|   ip.ip.flags_tree.ip.flags.df > 0
|   |   ip.ip.len <= 44
|   |   |   ip.ip.len <= 40: normal (28396.0)
|   |   |   ip.ip.len > 40: flood_tcp4 (298.0)
|   |   ip.ip.len > 44: normal (121021.0)
eth.eth.type = 0x000086dd
|   ipv6.ipv6.plen <= 325
|   |   ipv6.ipv6.plen <= 24
|   |   |   ipv6.ipv6.nxt <= 17: flood_tcp6 (203.0)
|   |   |   ipv6.ipv6.nxt > 17: normal (35.0)
|   |   ipv6.ipv6.plen > 24: normal (547.0)
|   ipv6.ipv6.plen > 325: flood_udp6 (10000.0)
eth.eth.type = 0x00000806: normal (88.0)
eth.eth.type = 0x0000888e: normal (6.0)

Number of Leaves  : 	11

Size of the tree : 	19


Time taken to build model: 6.75 seconds

=== Evaluation on training set ===
=== Summary ===

Correctly Classified Instances      170694              100      %
Incorrectly Classified Instances         0                0      %
Kappa statistic                          1
Mean absolute error                      0
Root mean squared error                  0
Relative absolute error                  0      %
Root relative squared error              0      %
Total Number of Instances           170694

=== Detailed Accuracy By Class ===

               TP Rate   FP Rate   Precision   Recall  F-Measure   ROC Area  Class
                 1         0          1         1         1          1        flood_tcp4
                 1         0          1         1         1          1        flood_tcp6
                 1         0          1         1         1          1        flood_udp4
                 1         0          1         1         1          1        flood_udp6
                 1         0          1         1         1          1        normal
Weighted Avg.    1         0          1         1         1          1

=== Confusion Matrix ===

      a      b      c      d      e   <-- classified as
    398      0      0      0      0 |      a = flood_tcp4
      0    203      0      0      0 |      b = flood_tcp6
      0      0  10000      0      0 |      c = flood_udp4
      0      0      0  10000      0 |      d = flood_udp6
      0      0      0      0 150093 |      e = normal
"""

PACKET_TYPE = {
  'NORMAL'    : 'NORMAL'
  'MALICIOUS' : {
    'TCP4'      :'TCP4',
    'TCP6'      :'TCP6',
    'UDP4'      :'UDP4',
    'UDP6'      :'UDP6',
    'UNDETECTED':'UNDETECTED'
  }
}

def detect(pkt, blocker=None, unblocker=None):
    global PACKET_TYPE
    detected = PACKET_TYPE.MALICIOUS.UNDETECTED

    if getattr(pkt[Ether], 'type') == int(b'0x00000800',16):
        if getattr(pkt[IP], 'flags') <= 0:
            if getattr(pkt[IP], 'proto') <= 6:
                detected = PACKET_TYPE.MALICIOUS.TCP4
            elif getattr(pkt[IP], 'proto') > 6:
                detected = PACKET_TYPE.MALICIOUS.UDP4
        elif getattr(pkt[IP], 'flags') > 0:
            if getattr(pkt[IP], 'len') <= 44:
                if getattr(pkt[IP], 'len') <= 40:
                    detected = PACKET_TYPE.NORMAL
                elif getattr(pkt[IP], 'len') > 40:
                    detected = PACKET_TYPE.MALICIOUS.TCP4
            elif getattr(pkt[IP], 'len') > 44:
                detected = PACKET_TYPE.NORMAL
    elif getattr(pkt[Ether], 'type') == int(b'0x000086dd',16):
        if getattr(pkt[IPv6], 'plen') <= 325:
            if getattr(pkt[IPv6], 'plen') <= 24:
                if getattr(pkt[IPv6], 'nh') <= 17:
                    detected = PACKET_TYPE.TCP6
                elif getattr(pkt[IPv6], 'nh') > 17:
                    detected = PACKET_TYPE.NORMAL
            elif getattr(pkt[IPv6], 'plen') > 24:
                detected = PACKET_TYPE.NORMAL
        elif getattr(pkt[IPv6], 'plen') > 325:
            detected = PACKET_TYPE.MALICIOUS.UDP6
    elif getattr(pkt[Ether], 'type') == int(b'0x00000806',16):
        detected = PACKET_TYPE.NORMAL
    elif getattr(pkt[Ether], 'type') == int(b'0x0000888e',16):
        detected = PACKET_TYPE.NORMAL

    if detected != PACKET_TYPE.NORMAL:
        print(detected)

if __name__ == '__main__':
    from scapy.all import *
    sniff(prn=detect)
