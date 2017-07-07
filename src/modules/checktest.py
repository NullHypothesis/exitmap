#!/usr/bin/env python2

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
Module to detect false negatives for <https://check.torproject.org>.
"""

import sys
import json
import logging
try:
    import urllib2
except ImportError:
    import urllib.request as urllib2

from util import exiturl

import stem.descriptor.server_descriptor as descriptor

log = logging.getLogger(__name__)

# exitmap needs this variable to figure out which relays can exit to the given
# destination(s).

destinations = [("check.torproject.org", 443)]


def fetch_page(exit_desc):
    """
    Fetch check.torproject.org and see if we are using Tor.
    """

    data = None
    url = exiturl(exit_desc.fingerprint)

    try:
        data = urllib2.urlopen("https://check.torproject.org/api/ip",
                               timeout=10).read()
    except Exception as err:
        log.debug("urllib2.urlopen says: %s" % err)
        return

    if not data:
        return

    try:
        check_answer = json.loads(data)
    except ValueError as err:
        log.warning("Couldn't parse JSON over relay %s: %s" % (url, data))
        return

    check_addr = check_answer["IP"].strip()
    if not check_answer["IsTor"]:
        log.error("Check thinks %s isn't Tor.  Desc addr is %s and check "
                  "addr is %s." % (url, exit_desc.address, check_addr))
    else:
        log.debug("Exit relay %s passed the check test." % url)


def probe(exit_desc, run_python_over_tor, run_cmd_over_tor, **kwargs):
    """
    Probe the given exit relay and look for check.tp.o false negatives.
    """

    run_python_over_tor(fetch_page, exit_desc)


def main():
    """
    Entry point when invoked over the command line.
    """

    desc = descriptor.ServerDescriptor("")
    desc.fingerprint = "bogus"
    desc.address = "0.0.0.0"
    fetch_page(desc)

    return 0


if __name__ == "__main__":
    sys.exit(main())
