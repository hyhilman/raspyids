import iptc
import ipaddress
import logging

DROP = "DROP"
IPv4 = 4
IPv6 = 6
TCP  = "tcp"
UDP  = "udp"
ICMP = "icmp"
INPUT  = "INPUT"
OUTPUT = "OUTPUT"

_protocols = [TCP, UDP, ICMP]
_logger = logging.getLogger('app.'+__name__)

def block(ip, protocol=None):
    try :
        src = ipaddress.ip_address(ip)
    except ValueError:
        _logger.error('Invalid source ip address to block')

    newRule = iptc.Rule()
    newRule.src = src.exploded
    if protocol != None:
        if protocol in _protocols:
            newRule.protocol = protocol
        else :
            _logger.error("Protocol %s not supported", protocol)

    newRule.Target = newRule.create_target(DROP)

    if src.version == IPv4:
        table = iptc.Table(iptc.Table.FILTER)
    elif src.version == IPv6:
        table = iptc.Table6(iptc.Table.FILTER)

    chain = iptc.Chain(table, INPUT)
    _logger.debug("Block IP %s", newRule.src)
    chain.insert_rule(newRule)

def unblock(ip):
    try :
        src = ipaddress.ip_address(ip)
    except ValueError:
        _logger.error('Invalid source ip address to block')

    if src.version == IPv4:
        table = iptc.Table(iptc.Table.FILTER)
    elif src.version == IPv6:
        table = iptc.Table6(iptc.Table.FILTER)

    for chain in table.chains:
        for rule in chain.rules:
            if rule.src.split('/')[0] == src.exploded:
                _logger.debug("Un-Block IP %s", rule.src)
                chain.delete_rule(rule)

def showrule(ip=None):
    if ip is IPv4:
        table = iptc.Table(iptc.Table.FILTER)
        __printrule(table)
    elif ip is IPv6:
        table = iptc.Table6(iptc.Table.FILTER)
        __printrule(table)
    else:
        showrule(IPv4)
        showrule(IPv6)

def __printrule(table):
    for chain in table.chains:
        print("=======================")
        print("Chain %s" % chain.name)
        for rule in chain.rules:
            print("Rule", "proto:", rule.protocol, "src:", rule.src, "dst:", \
            rule.dst, "in:", rule.in_interface, "out:", rule.out_interface)
            print("Matches:",)
            for match in rule.matches:
                print(match.name,)
            print("Target:",rule.target.name)
    print("=======================")
