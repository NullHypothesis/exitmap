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
Provides utility functions.
"""

import os
import re
import logging
try:
    import urllib2
except ImportError:
    import urllib.request as urllib2
import json
import tempfile
import errno

from stem.descriptor.reader import DescriptorReader


log = logging.getLogger(__name__)

# Holds the directory to which we can write temporary analysis results.

analysis_dir = None


def parse_log_lines(ports, log_line):
    """
    Extract the SOCKS and control port from Tor's log output.

    Both ports are written to the given dictionary.
    """

    log.debug("Tor says: %s" % log_line)

    if re.search(r"^.*Bootstrapped \d+%.*$", log_line):
        log.info(re.sub(r"^.*(Bootstrapped \d+%.*)$", r"Tor \1", log_line))

    socks_pattern = "Socks listener listening on port ([0-9]{1,5})."
    control_pattern = "Control listener listening on port ([0-9]{1,5})."

    match = re.search(socks_pattern, log_line)
    if match:
        ports["socks"] = int(match.group(1))
        log.debug("Tor uses port %d as SOCKS port." % ports["socks"])

    match = re.search(control_pattern, log_line)
    if match:
        ports["control"] = int(match.group(1))
        log.debug("Tor uses port %d as control port." % ports["control"])


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
    """
    Extract the source port from a stream event.
    """

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
    Return a list of the fingerprints of all relays in the given country code.

    The fingerprints are obtained by querying Onionoo.
    """

    country_code = country_code.lower()
    onionoo_url = "https://onionoo.torproject.org/details?country="

    log.info("Attempting to fetch all relays with country code \"%s\" "
             "from Onionoo." % country_code)

    f = urllib2.urlopen("%s%s" % (onionoo_url, country_code))
    data = f.read().decode('utf-8')
    response = json.loads(data)

    fingerprints = [desc["fingerprint"] for desc in response["relays"]]

    log.info("Onionoo gave us %d (exit and non-exit) fingerprints." %
             len(fingerprints))

    return fingerprints


def exiturl(exit_fpr):
    """
    Return a Metrics link for the exit relay fingerprint.
    """

    return "<https://metrics.torproject.org/rs.html#details/%s>" % exit_fpr


def dump_to_file(blurb, exit_fpr):
    """
    Dump the given blurb to a randomly generated file which contains exit_fpr.

    This function is useful to save data obtained from bad exit relays to file
    for later analysis.
    """
    if analysis_dir is None:
        fd, file_name = tempfile.mkstemp(prefix="%s_" % exit_fpr)

    else:
        try:
            os.makedirs(analysis_dir)
        except OSError as err:
            if err.errno != errno.EEXIST:
                raise
        fd, file_name = tempfile.mkstemp(prefix="%s_" % exit_fpr,
                                         dir=analysis_dir)

    try:
        with open(file_name, "w") as fd:
            fd.write(blurb)
    except IOError as err:
        log.warning("Couldn't write to \"%s\": %s" % (file_name, err))
        return None

    log.debug("Wrote %d-length blurb to file \"%s\"." %
                 (len(blurb), file_name))

    return file_name


def new_request(url, data=None):
    """
    Return a request object whose HTTP header resembles TorBrowser.
    """

    request = urllib2.Request(url, data)

    # Try to resemble the HTTP request of TorBrowser as closely as possible.
    # Note that the order of header fields is also relevant but urllib2 uses a
    # dictionary for headers, which is orderless.

    request.add_header("User-Agent", "Mozilla/5.0 (Windows NT 6.1; rv:60.0) "
                                     "Gecko/20100101 Firefox/60.0")
    request.add_header("Accept", "text/html,application/xhtml+xml,"
                                 "application/xml;q=0.9,*/*;q=0.8")
    request.add_header("Accept-Language", "en-US,en;q=0.5")
    request.add_header("Accept-Encoding", "gzip, deflate, br")
    request.add_header("Upgrade-Insecure-Requests", "1")

    return request
