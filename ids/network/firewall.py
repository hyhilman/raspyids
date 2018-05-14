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

__ip = [IPv4, IPv6]
__protocols = [TCP, UDP, ICMP]
__logger = logging.getLogger('app.'+__name__)

def block(ip, protocol=None):
    try :
        src = ipaddress.ip_address(ip)
        if src.version == IPv4:
            table = iptc.Table(iptc.Table.FILTER)
        elif src.version == IPv6:
            table = iptc.Table6(iptc.Table.FILTER)
    except ValueError:
        __logger.error('Invalid source ip address to block')
        raise Exception("Error")

    blocked = False
    for chain in table.chains:
        for rule in chain.rules:
            if rule.src.split('/')[0] == src.exploded:
                __logger.debug("IP address is already blocked %s", rule.src)
                blocked = True

    if blocked is False:
        newRule = iptc.Rule()
        newRule.src = src.exploded

        if protocol != None:
            if protocol in __protocols:
                newRule.protocol = protocol
            else :
                __logger.error("Protocol %s not supported", protocol)
        newRule.Target = newRule.create_target(DROP)

        chain = iptc.Chain(table, INPUT)
        # chain.insert_rule(newRule)

        chain = iptc.Chain(table, OUTPUT)
        # chain.insert_rule(newRule)
        __logger.debug("Block IP %s", newRule.src)

def unblock(ip):
    try :
        src = ipaddress.ip_address(ip)
        if src.version == IPv4:
            table = iptc.Table(iptc.Table.FILTER)
        elif src.version == IPv6:
            table = iptc.Table6(iptc.Table.FILTER)

        for chain in table.chains:
            for rule in chain.rules:
                if rule.src.split('/')[0] == src.exploded:
                    __logger.debug("Un-Block IP %s", rule.src)
                    chain.delete_rule(rule)
    except ValueError:
        __logger.error('Invalid source ip address to block')

def show(ip=None):
    if ip is IPv4:
        table = iptc.Table(iptc.Table.FILTER)
        __printrule(table)
    elif ip is IPv6:
        table = iptc.Table6(iptc.Table.FILTER)
        __printrule(table)
    else:
        show(IPv4)
        show(IPv6)

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
