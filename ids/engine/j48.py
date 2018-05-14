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
    try :
        ip = pkt[IP].src
        if getattr(pkt[Ether], 'type') == int(b'0x00000800',16):
            if getattr(pkt[IP], 'tos') == int(b'0x00000000',16):
                if getattr(pkt[IP], 'proto') <= 6:
                    if getattr(pkt[TCP], 'dataofs')*4 <= 24:
                        logger.warning("dos_tcp4 from %s", ip)
                        blocker(ip)
                    elif getattr(pkt[TCP], 'dataofs')*4 > 24:
                        if getattr(pkt[TCP], 'window') <= 15725:
                            logger.debug("incoming redis packet from %s", ip)
                        elif getattr(pkt[TCP], 'window') > 15725:
                            logger.debug("incoming mqtt4 packet from %s", ip)
                elif getattr(pkt[IP], 'proto') > 6:
                    if getattr(pkt[IP], 'flags') == 2:
                        logger.debug("incoming coap4 packet from %s", ip)
                    elif getattr(pkt[IP], 'flags') == 0:
                        logger.warning("dos_udp4 from %s", ip)
                        blocker(ip)
            if getattr(pkt[IP], 'tos') == int(b'0x00000010',16):
                logger.debug("incoming ssh packet from %s", ip)
            elif getattr(pkt[IP], 'tos') == int(b'0x000000b8',16):
                logger.debug("incoming ntp packet from %s", ip)
        elif getattr(pkt[Ether], 'type') == int(b'0x000086dd',16):
            if getattr(pkt[IPv6], 'hlim') <= 64:
                if getattr(pkt[IPv6], 'nh') <= 6:
                    if getattr(pkt[TCP], 'dataofs')*4 <= 24:
                        ip = pkt[IP].src
                        logger.warning("dos_tcp6 from %s", ip)
                        blocker(ip)
                    elif getattr(pkt[TCP], 'dataofs')*4 > 24:
                        logger.debug("incoming mqtt6 packet from %s", ip)
                if getattr(pkt[IPv6], 'nh') > 6:
                    if getattr(pkt[IPv6], 'nh') <= 6:
                        ip = pkt[IP].src
                        logger.warning("dos_udp6 from %s", ip)
                        blocker(ip)
                    if getattr(pkt[IPv6], 'nh') > 6:
                        logger.debug("incoming coap6 packet from %s", ip)
            if getattr(pkt[IPv6], 'hlim') > 64:
                logger.debug("incoming ICMPv6 packet from %s", ip)
        elif getattr(pkt[Ether], 'type') == int(b'0x0000888e',16):
            logger.debug("incoming eapol packet from %s", ip)
        elif getattr(pkt[Ether], 'type') == int(b'0x00000806',16):
            logger.debug("incoming arp packet from %s", ip)
    except IndexError:
        pass
