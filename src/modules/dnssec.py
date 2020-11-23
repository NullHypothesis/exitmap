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
Detect exit relays whose resolver does not validate DNSSEC.
"""

import sys
import logging
import socket

import error
import util
import torsocks

log = logging.getLogger(__name__)

destinations = None

# The following is a deliberately broken DNSSEC domain.  If we are able to
# resolve it, it means that our resolver does not validate DNSSEC.

BROKEN_DOMAIN = "www.dnssec-failed.org"


def test_dnssec(exit_fpr):
    """
    Test if broken DNSSEC domain can be resolved.
    """

    exit_url = util.exiturl(exit_fpr)
    sock = torsocks.torsocket()
    sock.settimeout(10)

    # Resolve domain using Tor's SOCKS extension.

    try:
        ipv4 = sock.resolve(BROKEN_DOMAIN)
    except error.SOCKSv5Error as err:
        log.debug("%s did not resolve broken domain because: %s.  Good." %
                  (exit_url, err))
        return
    except socket.timeout as err:
        log.debug("Socket over exit relay %s timed out: %s" % (exit_url, err))
        return
    except Exception as err:
        log.debug("Could not resolve domain because: %s" % err)
        return

    log.critical("%s resolved domain to %s" % (exit_url, ipv4))


def probe(exit_desc, run_python_over_tor, run_cmd_over_tor, **kwargs):
    """
    Test if exit relay can resolve broken domain.
    """

    run_python_over_tor(test_dnssec, exit_desc.fingerprint)


if __name__ == "__main__":
    log.critical("Module can only be run over Tor, not stand-alone.")
    sys.exit(1)
