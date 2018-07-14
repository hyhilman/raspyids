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
FORWARD = "FORWARD"

__ip = [IPv4, IPv6]
__protocols = [TCP, UDP, ICMP]
__logger = logging.getLogger('app.'+__name__)

def block(ip, protocol=None):
    try :
        src = ipaddress.ip_address(ip)
        if src.version == IPv4:
            table = iptc.Table(iptc.Table.FILTER)
        elif src.version == IPv6:
            table = iptc.Table6(iptc.Table6.FILTER)
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

        iptc.Chain(table, INPUT).insert_rule(newRule)
        iptc.Chain(table, OUTPUT).insert_rule(newRule)
        iptc.Chain(table, FORWARD).insert_rule(newRule)

        # chain = iptc.Chain(table, INPUT)
        # # chain.insert_rule(newRule)
        #
        # chain = iptc.Chain(table, OUTPUT)
        # # chain.insert_rule(newRule)
        #
        # chain = iptc.Chain(table, FORWARD)
        # # chain.insert_rule(newRule)
        __logger.warning("Block IP %s", newRule.src)

def unblock(ip=None):
    if ip==None:
        iptc.Chain(iptc.Table(iptc.Table.FILTER), INPUT).flush()
        iptc.Chain(iptc.Table(iptc.Table.FILTER), OUTPUT).flush()
        iptc.Chain(iptc.Table(iptc.Table.FILTER), FORWARD).flush()
        iptc.Chain(iptc.Table6(iptc.Table6.FILTER), INPUT).flush()
        iptc.Chain(iptc.Table6(iptc.Table6.FILTER), OUTPUT).flush()
        iptc.Chain(iptc.Table6(iptc.Table6.FILTER), FORWARD).flush()
    else:
        try :
            src = ipaddress.ip_address(ip)
            if src.version == IPv4:
                table = iptc.Table(iptc.Table.FILTER)
            elif src.version == IPv6:
                table = iptc.Table6(iptc.Table6.FILTER)

            for chain in table.chains:
                for rule in chain.rules:
                    if rule.src.split('/')[0] == src.exploded:
                        __logger.debug("Un-Block IP %s", rule.src)
                        chain.delete_rule(rule)
        except ValueError:
            __logger.error('Invalid source ip address to block')
            __logger.warning("Block IP %s", newRule.src)


def show(ip=None):
    if ip is IPv4:
        table = iptc.Table(iptc.Table.FILTER)
        __logger.debug("Print IPv4 firewall rules")
        __printrule(table)
    elif ip is IPv6:
        table = iptc.Table6(iptc.Table6.FILTER)
        __logger.debug("Print IPv6 firewall rules")
        __printrule(table)
    else:
        show(IPv4)
        show(IPv6)

def __printrule(table):
    output = ''
    for chain in table.chains:
        output += "=======================\n"
        # print("Chain %s" % chain.name)
        output += "Chain %s" % chain.name
        for rule in chain.rules:
            output += "Rule"+ " proto: "+ rule.protocol+ " src: "+ rule.src+ " dst: "+ \
            rule.dst+ " in: "+ rule.in_interface+ " out:", rule.out_interface
            # print("Rule", "proto:", rule.protocol, "src:", rule.src, "dst:", \
            # rule.dst, "in:", rule.in_interface, "out:", rule.out_interface)
            output += "Matches:"
            # print("Matches:",)
            for match in rule.matches:
                output += match.name
                # print(match.name,)
            output += "Target:"+rule.target.name
            # print("Target:",rule.target.name)
    output += "=======================\n"
    print(output)
