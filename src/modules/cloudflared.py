#!/usr/bin/env python3

# Copyright 2016 Philipp Winter <phw@nymity.ch>
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
Check if a web site returns a CloudFlare CAPTCHA.
"""

import sys
import io
import gzip
import http.client
import collections
import logging

import util

log = logging.getLogger(__name__)

destinations = [("www.cloudflare.com", 443)]
DOMAIN, PORT = destinations[0]

CAPTCHA_SIGN = b"Attention Required! | Cloudflare"

# Mimic Tor Browser's request headers, so CloudFlare won't return a 403 because
# it thinks we are a bot.

HTTP_HEADERS = [("Host", DOMAIN),
                ("User-Agent", "Mozilla/5.0 (Windows NT 6.1; rv:52.0) "
                 "Gecko/20100101 Firefox/52.0"),
                ("Accept", "text/html,application/xhtml+xml,"
                           "application/xml;q=0.9,*/*;q=0.8"),
                ("Accept-Language", "en-US,en;q=0.5"),
                ("Accept-Encoding", "gzip, deflate, br"),
                ("Connection", "keep-alive"),
                ("Upgrade-Insecure-Requests", "1")]


def decompress(data):
    """
    Decompress gzipped HTTP response.
    """

    try:
        buf = io.StringIO(data)
        fileobj = gzip.GzipFile(fileobj=buf)
        data = fileobj.read()
    except Exception:
        pass

    return data


def is_cloudflared(exit_fpr):
    """
    Check if site returns a CloudFlare CAPTCHA.
    """

    exit_url = util.exiturl(exit_fpr)
    log.debug("Probing exit relay \"%s\"." % exit_url)

    conn = http.client.HTTPSConnection(DOMAIN, PORT)
    conn.request("GET", "/", headers=collections.OrderedDict(HTTP_HEADERS))
    try:
        response = conn.getresponse()
    except Exception as err:
        log.warning("urlopen() over %s says: %s" % (exit_url, err))
        return

    data = decompress(response.read())
    if not data:
        log.warning("Did not get any data over %s." % exit_url)
        return

    if data and (CAPTCHA_SIGN in data):
        log.info("Exit %s sees a CAPTCHA." % exit_url)
    else:
        log.info("Exit %s does not see a CAPTCHA." % exit_url)


def probe(exit_desc, run_python_over_tor, run_cmd_over_tor, **kwargs):
    """
    Check if exit relay sees a CloudFlare CAPTCHA.
    """

    run_python_over_tor(is_cloudflared, exit_desc.fingerprint)


if __name__ == "__main__":
    is_cloudflared("bogus-fingerprint")
    sys.exit(0)
