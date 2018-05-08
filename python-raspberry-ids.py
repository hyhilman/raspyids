from output import logger
from network import firewall
import logging

logger.init()
firewall.block('192.168.42.1')
firewall.unblock('192.168.42.1')
# firewall.showrule()
