#!/usr/bin/env python

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
Module to detect false positives for https://check.torproject.org.
"""

import urllib2

import log

logger = log.get_logger()

# exitmap needs this variable to figure out which relays can exit to the given
# destination(s).

destinations = [("check.torproject.org", 443)]


def probe(exit_fpr, cmd):
    """
    Probe the given exit relay and look for check.tp.o false positives.
    """

    logger.debug("Now probing exit relay "
                 "<https://globe.torproject.org/#/relay/%s>." % exit_fpr)

    data = None

    try:
        data = urllib2.urlopen("https://check.torproject.org",
                               timeout=10).read()
    except urllib2.URLError as err:
        logger.error("urllib2.urlopen says: %s" % err)

    if not data:
        return

    # This is the string, we are looking for in the response.

    identifier = "Congratulations. This browser is configured to use Tor."

    if not (identifier in data):
        logger.error("Detected false negative for "
                     "<https://globe.torproject.org/#/relay/%s>." % exit_fpr)
    else:
        logger.debug("Exit relay <https://globe.torproject.org/#/relay/%s> "
                     "passed the check test." % exit_fpr)

def main():
    """
    Entry point when invoked over the command line.
    """

    probe("n/a", None)

    return 0


if __name__ == "__main__":
    exit(main())
