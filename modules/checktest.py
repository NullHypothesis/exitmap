#!/usr/bin/env python

"""
Module to detect false positives for https://check.torproject.org.
"""

import mysocks
import socket
import urllib2

import log

logger = log.getLogger()

# exitmap needs this variable to figure out which relays can exit to the given
# destination(s).
destinations = [("check.torproject.org", 443)]

def probe( exitFpr, queue, circID ):

    logger.info("I'm the module which is probing exit relay \"%s\"." % exitFpr)

    mysocks.setdefaultproxy(mysocks.PROXY_TYPE_SOCKS5, "127.0.0.1", 10000)
    mysocks.setqueue(queue, circID)
    socket.socket = mysocks.socksocket

    data = None
    try:
        data = urllib2.urlopen("https://check.torproject.org",
                               timeout=10).read()
    except urllib2.URLError as err:
        logger.error("urllib2.urlopen says: %s" % err)

    if not data:
        return

    identifier = "Congratulations. This browser is configured to use Tor."
    if not (identifier in data):
        logger.error("Detected false negative for \"%s\".  " \
                     "Full dump below." % exitFpr)
        logger.error(data)
    else:
        logger.info("Exit relay \"%s\" passed the check test." % exitFpr)
