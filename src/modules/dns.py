# Copyright 2013, 2014 Philipp Winter <phw@nymity.ch>
#
# This file is part of exitmap.
#
# exitmap is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# exitmap is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with exitmap.  If not, see <http://www.gnu.org/licenses/>.

"""
Module to detect malfunctioning DNS resolution.
"""

import log
import mysocks
from util import exiturl

logger = log.get_logger()

destinations = None


def resolve(exit_fpr, domain, whitelist):
    """
    Resolve a `domain' and compare it to the `whitelist'.

    If the domain is not part of the whitelist, an error is logged.
    """

    sock = mysocks.socksocket()

    # Resolve the domain using Tor's SOCKS extension.

    try:
        ipv4 = sock.resolve(domain)
    except mysocks.GeneralProxyError as err:
        logger.debug("Exit relay %s could not resolve IPv4 address for "
                     "\"%s\" because: %s" % (exiturl(exit_fpr), domain, err))
        return

    if ipv4 not in whitelist:
        logger.critical("Exit relay %s returned unexpected IPv4 address %s "
                        "for domain %s" % (exiturl(exit_fpr), ipv4, domain))
    else:
        logger.debug("IPv4 address of domain %s as expected for %s." %
                     (domain, exiturl(exit_fpr)))


def probe(exit_fpr, cmd):
    """
    Probe the given exit relay and check if the domains resolve as expected.
    """

    # Format: <domain> : <ipv4_addresses>

    domains = {
        "www.youporn.com": ["31.192.116.24"],
        "youporn.com": ["31.192.116.24"],
        "www.torproject.org": ["38.229.72.14", "93.95.227.222", "86.59.30.40",
                               "38.229.72.16", "82.195.75.101",
                               "154.35.132.70"],
        "www.wikileaks.org": ["95.211.113.131", "95.211.113.154",
                              "91.218.114.210", "91.218.244.152",
                              "195.35.109.53", "195.35.109.44",
                              "91.218.244.151"],
        "www.i2p2.de": ["91.143.92.136"],
        "thepiratebay.se": ["141.101.118.194"],
        "torrentfreak.com": ["162.159.245.23", "162.159.246.23"],
        "github.com": ["192.30.252.128", "192.30.252.129", "192.30.252.131",
                       "192.30.252.130"],
        "blockchain.info": ["141.101.112.196", "190.93.243.195"],
    }

    for domain in domains.iterkeys():
        resolve(exit_fpr, domain, domains[domain])
