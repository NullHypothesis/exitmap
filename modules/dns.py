#!/usr/bin/env python

"""
Module to detect malfunctioning DNS resolution.
"""

import log
import const
import mysocks

logger = log.getLogger()

destinations = None

def resolve( exitFpr, domain, whitelist ):
    """
    Resolve a `domain' and compare it to the `whitelist'.

    If the domain is not part of the whitelist, an error is logged.
    """

    sock = mysocks.socksocket()
    sock.setproxy(mysocks.PROXY_TYPE_SOCKS5, "127.0.0.1", const.TOR_SOCKS_PORT)
    # Resolve the domain using Tor's SOCKS extension.
    ipv4 = sock.resolve(domain)

    if ipv4 not in whitelist:
        logger.error("Exit relay %s returned unexpected IPv4 address for " \
                     "\"%s\": %s." % (exitFpr, domain, ipv4))
    else:
        logger.info("IPv4 address of \"%s\" as expected for %s." %
                    (domain, exitFpr))

def probe( exitFpr, cmd ):
    """
    Probe the given exit relay and check if the domains resolve as expected.
    """

    # Format: <domain> : <ipv4_addresses>
    domains = {
        "youporn.com" : ["31.192.116.24"],
        "www.torproject.org" : ["38.229.72.14", "93.95.227.222", "86.59.30.40",
                                "38.229.72.16", "82.195.75.101"],
        "www.wikileaks.org" : ["95.211.113.131", "95.211.113.154"]
    }

    for domain in domains.iterkeys():
        resolve(exitFpr, domain, domains[domain])
