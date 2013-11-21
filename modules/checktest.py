#!/usr/bin/env python

"""
Module to detect false positives for https://check.torproject.org.
"""

import socks
import socket
import urllib2

import log
import command

logger = log.getLogger()

targets = [("check.torproject.org", 443)]

def probe( cmd, count=1 ):

    logger.info("This is scan #%d" % count)

    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 10000)
    socket.socket = socks.socksocket

    data = urllib2.urlopen("https://check.torproject.org", timeout=10).read()

    identifier = "Congratulations. This browser is configured to use Tor."
    if not (identifier in data):
        logger.error("Detected false negative.  Full dump below.")
        logger.error(data)
    else:
        logger.info("Passed the check test.")

def main():
    """
    Entry point when invoked over the command line.
    """

    probe(command.new(None))

    return 0

if __name__ == "__main__":
    exit(main())
