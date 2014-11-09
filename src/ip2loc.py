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

import sys
import json
import urllib2

import geoip
import log

logger = log.get_logger()


def binary_search(begin, ip, end):
    middle = begin + ((end - begin) / 2)

    if ip < int(geoip.db[middle][0]):
        if (middle - 1) == end:
            return ""

        return binary_search(begin, ip, middle - 1)
    elif ip > int(geoip.db[middle][1]):
        if (middle + 1) == begin:
            return ""

        return binary_search(middle + 1, ip, end)
    else:
        return "%s" % geoip.db[middle][2]


def resolve(ip):
    d1, d2, d3, d4 = ip.split('.')

    return binary_search(0, int(d1) << 24 | int(d2) << 16 |
                         int(d3) << 8 | int(d4), len(geoip.db) - 1)


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

    logger.info("Onionoo gave us %d fingerprints." % len(fingerprints))

    return fingerprints
