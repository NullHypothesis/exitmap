#!/usr/bin/env python

# Copyright 2013-2015 Philipp Winter <phw@nymity.ch>
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
import urllib2

import log
from util import exiturl

logger = log.get_logger()

# exitmap needs this variable to figure out which relays can exit to the given
# destination(s).

destinations = [("check.torproject.org", 443)]


def fetch_page(exit_desc):
    """
    Fetch check.torproject.org and see if we are using Tor.
    """

    data = None

    try:
        data = urllib2.urlopen("https://check.torproject.org",
                               timeout=10).read()
    except Exception as err:
        logger.debug("urllib2.urlopen says: %s" % err)

    if not data:
        return

    # This is the string, we are looking for in the response.

    identifier = "Congratulations. This browser is configured to use Tor."

    url = exiturl(exit_desc.fingerprint)
    if not (identifier in data):
        logger.error("Detected false negative for %s." % url)
    else:
        logger.debug("Exit relay %s passed the check test." % url)


def probe(exit_desc, run_python_over_tor, run_cmd_over_tor):
    """
    Probe the given exit relay and look for check.tp.o false negatives.
    """

    run_python_over_tor(fetch_page, exit_desc)


def main():
    """
    Entry point when invoked over the command line.
    """

    probe("n/a", None)

    return 0


if __name__ == "__main__":
    sys.exit(main())
