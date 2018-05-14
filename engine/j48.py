from scapy.all import *
import logging
logger = logging.getLogger('app.'+__name__)

"""=== Model information ===

Filename:     275featuresj48gr.model
Scheme:weka.classifiers.trees.J48 -C 0.25 -M 2
Relation:noWiresharkFrameLayerAndStringIdentifier
Attributes:   275
[list of attributes omitted]

=== Classifier model ===

J48 pruned tree
------------------

eth.type = 0x00000800
|   ip.dsfield = 0x00000000
|   |   ip.proto <= 6
|   |   |   tcp.hdr_len <= 24: dos_tcp4 (398.0)
|   |   |   tcp.hdr_len > 24
|   |   |   |   tcp.window_size <= 15725: redis (61952.0)
|   |   |   |   tcp.window_size > 15725: mqtt4 (391.0)
|   |   ip.proto > 6
|   |   |   ip.flags = 0x00000002: coap4 (60.0)
|   |   |   ip.flags = 0x00000000: dos_udp4 (100.0)
|   ip.dsfield = 0x00000010: ssh (18689.0)
|   ip.dsfield = 0x000000b8: ntp (28.0)
eth.type = 0x000086dd
|   ipv6.hlim <= 64
|   |   ipv6.nxt <= 6
|   |   |   tcp.hdr_len <= 24: dos_tcp6 (303.0)
|   |   |   tcp.hdr_len > 24: mqtt6 (390.0)
|   |   ipv6.nxt > 6
|   |   |   ipv6.plen <= 20: dos_udp6 (100.0)
|   |   |   ipv6.plen > 20: coap6 (60.0)
|   ipv6.hlim > 64: icmpv6 (61.0)
eth.type = 0x0000888e: eapol (6.0)
eth.type = 0x00000806: arp (1270.0)

Number of Leaves  : 	14

Size of the tree : 	24

"""

def detect(pkt, blocker=None, unblocker=None):
    if getattr(pkt[Ether], 'type') == int(b'0x00000800',16):
        if getattr(pkt[IP], 'tos') == int(b'0x00000000',16):
            if getattr(pkt[IP], 'proto') <= 6:
                if getattr(pkt[TCP], 'dataofs')*4 <= 24:
                    print("TCP DOS")
                elif getattr(pkt[TCP], 'dataofs')*4 > 24:
                    if getattr(pkt[TCP], 'window') <= 15725:
                        print(getattr(pkt[TCP], 'window'))
                        print("redis")
                    elif getattr(pkt[TCP], 'window') > 15725:
                        print("mqtt4")
            elif getattr(pkt[IP], 'proto') > 6:
                if getattr(pkt[IP], 'flags') == 2:
                    print("coap4")
                elif getattr(pkt[IP], 'flags') == 0:
                    print("dos_udp4")
        if getattr(pkt[IP], 'tos') == int(b'0x00000010',16):
            print("ssh")
        elif getattr(pkt[IP], 'tos') == int(b'0x000000b8',16):
            print("ntp")
    elif getattr(pkt[Ether], 'type') == int(b'0x000086dd',16):
        if getattr(pkt[IPv6], 'hlim') <= 64:
            if getattr(pkt[IPv6], 'nh') <= 6:
                if getattr(pkt[TCP], 'dataofs')*4 <= 24:
                    print("dos_tcp6")
                elif getattr(pkt[TCP], 'dataofs')*4 > 24:
                    print("mqtt6")
            if getattr(pkt[IPv6], 'nh') > 6:
                if getattr(pkt[IPv6], 'nh') <= 6:
                    print("dos_udp6")
                if getattr(pkt[IPv6], 'nh') > 6:
                    print("coap6")
        if getattr(pkt[IPv6], 'hlim') > 64:
            print("ICMPv6")
    elif getattr(pkt[Ether], 'type') == int(b'0x0000888e',16):
        print("eapol")
    elif getattr(pkt[Ether], 'type') == int(b'0x00000806',16):
        print("arp")
