#!/usr/bin/env python2

# Copyright 2014-2016 Philipp Winter <phw@nymity.ch>
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
This module attempts to fetch a simple web page.  If this succeeds, we know
that the relay (probably) has enough file descriptors.
"""

import sys
import re
import logging
import urllib.request, urllib.error, urllib.parse

from util import exiturl

import stem.descriptor.server_descriptor as descriptor
import socks

log = logging.getLogger(__name__)

destinations = [("people.torproject.org", 443)]


def fetch_page(exit_desc):

    expected = "This file is to check if your exit relay has enough file " \
               "descriptors to fetch it."

    exit_url = exiturl(exit_desc.fingerprint)

    log.debug("Probing exit relay %s." % exit_url)

    data = None
    try:
        data = urllib.request.urlopen("https://people.torproject.org/~phw/check_file",
                               timeout=10).read().decode("utf-8")
    except Exception as err:
        log.warning("urllib.request.urlopen for %s says: %s." %
                    (exit_desc.fingerprint, err))
        return

    if not data:
        log.warning("Exit relay %s did not return data." % exit_url)
        return

    data = data.strip()

    if not re.match(expected, data):
        log.warning("Got unexpected response from %s: %s." % (exit_url, data))
    else:
        log.debug("Exit relay %s worked fine." % exit_url)


def probe(exit_desc, run_python_over_tor, run_cmd_over_tor, **kwargs):
    """
    Attempts to fetch a small web page and yells if this fails.
    """

    run_python_over_tor(fetch_page, exit_desc)


def main():
    """
    Entry point when invoked over the command line.
    """

    desc = descriptor.ServerDescriptor("")
    desc.fingerprint = "bogus"
    fetch_page(desc)

    return 0

if __name__ == "__main__":
    sys.exit(main())
