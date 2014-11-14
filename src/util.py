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

import re
import os
import urllib2
import json
import tempfile
import atexit

from stem.descriptor.reader import DescriptorReader

import log

logger = log.get_logger()


def create_temp_torsocks_conf(socks_port):
    """
    Write a temporary config file for torsocks to disk.

    The name of the temporary file is returned and the file is removed when the
    program finishes.
    """

    content = "TorAddress 127.0.0.1\nTorPort %d\n" % socks_port

    fd, file_path = tempfile.mkstemp(prefix="torsocks_")
    os.write(fd, content)
    os.close(fd)

    # Remove the file when the program finishes.

    atexit.register(os.unlink, file_path)

    return file_path


def parse_log_lines(ports, log_line):
    """
    Extract the SOCKS and control port from Tor's log output.

    Both ports are written to the given dictionary.
    """

    logger.debug("Tor says: %s" % log_line)

    socks_pattern = "Socks listener listening on port ([0-9]{1,5})."
    control_pattern = "Control listener listening on port ([0-9]{1,5})."

    match = re.search(socks_pattern, log_line)
    if match:
        ports["socks"] = int(match.group(1))
        logger.debug("Tor uses port %d as SOCKS port." % ports["socks"])

    match = re.search(control_pattern, log_line)
    if match:
        ports["control"] = int(match.group(1))
        logger.debug("Tor uses port %d as control port." % ports["control"])


def relay_in_consensus(fingerprint, cached_consensus_path):
    """
    Check if a relay is part of the consensus.

    If the relay identified by `fingerprint' is part of the given `consensus',
    True is returned.  If not, False is returned.
    """

    fingerprint = fingerprint.upper()

    with DescriptorReader(cached_consensus_path) as reader:
        for descriptor in reader:
            if descriptor.fingerprint == fingerprint:
                return True

    return False


def get_source_port(stream_line):
    pattern = "SOURCE_ADDR=[0-9\.]{7,15}:([0-9]{1,5})"
    match = re.search(pattern, stream_line)

    if match:
        return int(match.group(1))

    return None


def extract_pattern(line, pattern):
    """
    Look for the given 'pattern' in 'line'.

    If it is found, the match is returned.  Otherwise, 'None' is returned.
    """

    match = re.search(pattern, line)

    if match:
        return match.group(1)

    return None


def get_relays_in_country(country_code):
    """
    Return a list of the fingerprint of all relays in the given country code.

    The fingerprints are obtained by querying Onionoo.  In case of an error, an
    empty list is returned.
    """

    country_code = country_code.lower()
    onionoo_url = "https://onionoo.torproject.org/details?country="

    logger.info("Attempting to fetch all relays with country code \"%s\" "
                "from Onionoo." % country_code)

    try:
        data = urllib2.urlopen("%s%s" % (onionoo_url, country_code)).read()
    except Exception as err:
        logger.warning("urlopen() failed: %s" % err)
        return []

    try:
        response = json.loads(data)
    except ValueError as err:
        logger.warning("json.loads() failed: %s" % err)
        return []

    fingerprints = [desc["fingerprint"] for desc in response["relays"]]

    logger.info("Onionoo gave us %d (exit and non-exit) fingerprints." %
                len(fingerprints))

    return fingerprints
