#!/usr/bin/env python3

# Copyright 2013-2017 Philipp Winter <phw@nymity.ch>
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

import logging

import torsocks
import socket
import error
from util import exiturl

import dns.resolver

log = logging.getLogger(__name__)

destinations = None
domains = {
    "www.youporn.com": [],
    "youporn.com": [],
    "www.torproject.org": [],
    "www.i2p2.de": [],
    "torrentfreak.com": [],
    "blockchain.info": [],
}


def setup():
    """
    Populate the `domains' dictionary by asking our system DNS resolver.
    """

    log.debug("Populating domain dictionary.")

    for domain in list(domains.keys()):
        response = dns.resolver.query(domain)
        for record in response:
            log.debug("Domain %s maps to %s." % (domain, record.address))
            domains[domain].append(record.address)

    log.info("Domain whitelist: %s" % str(domains))


def resolve(exit_desc, domain, whitelist):
    """
    Resolve a `domain' and compare it to the `whitelist'.

    If the domain is not part of the whitelist, an error is logged.
    """

    exit = exiturl(exit_desc.fingerprint)
    sock = torsocks.torsocket()
    sock.settimeout(10)

    # Resolve the domain using Tor's SOCKS extension.

    try:
        ipv4 = sock.resolve(domain)
    except error.SOCKSv5Error as err:
        log.debug("Exit relay %s could not resolve IPv4 address for "
                  "\"%s\" because: %s" % (exit, domain, err))
        return
    except socket.timeout as err:
        log.debug("Socket over exit relay %s timed out: %s" % (exit, err))
        return
    except EOFError as err:
        log.debug("EOF error: %s" % err)
        return

    if ipv4 not in whitelist:
        log.critical("Exit relay %s returned unexpected IPv4 address %s "
                     "for domain %s" % (exit, ipv4, domain))
    else:
        log.debug("IPv4 address of domain %s as expected for %s." %
                  (domain, exit))


def probe(exit_desc, run_python_over_tor, run_cmd_over_tor, **kwargs):
    """
    Probe the given exit relay and check if all domains resolve as expected.
    """

    for domain in list(domains.keys()):
        run_python_over_tor(resolve, exit_desc, domain, domains[domain])


if __name__ == "__main__":
    log.critical("Module can only be run over Tor, and not stand-alone.")
