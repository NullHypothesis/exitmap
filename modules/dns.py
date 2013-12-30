#!/usr/bin/env python

"""
Module to detect malfunctioning DNS resolution.
"""

import log
import const
import mysocks

logger = log.getLogger()

destinations = None

def probe( exitFpr, cmd ):
    """
    Probe the given exit relay and check if the resolved domain is as expected.
    """

    whitelist = [
        "38.229.72.14",
        "93.95.227.222",
        "86.59.30.40",
        "38.229.72.16",
        "82.195.75.101"
    ]

    sock = mysocks.socksocket()
    sock.setproxy(mysocks.PROXY_TYPE_SOCKS5, "127.0.0.1", const.TOR_SOCKS_PORT)
    ipv4 = sock.resolve("www.torproject.org")

    if ipv4 not in whitelist:
        logger.error("Exit relay %s returned unexpected IPv4 address: %s" %
                     (exitFpr, ipv4))
    else:
        logger.info("IPv4 address as expected: %s" % ipv4)
