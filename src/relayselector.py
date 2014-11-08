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

import os
import sys
import argparse

import stem
import stem.descriptor

import log
import ip2loc

logger = log.get_logger()


def parse_cmd_args():
    """
    Parses and returns command line arguments.
    """

    parser = argparse.ArgumentParser(description="%s selects a subset of Tor "
                                     "exit relays." % sys.argv[0])

    parser.add_argument("-b", "--badexit", action="store_true", default=None,
                        help="Select bad exit relays.")

    parser.add_argument("-c", "--countrycode", type=str, default=None,
                        help="Two-letter country code to select.")

    parser.add_argument("-d", "--data-dir", type=str, default=None,
                        help="Tor's data directory.")

    parser.add_argument("-v", "--version", type=str, default=None,
                        help="Show relays with a specific version.")

    parser.add_argument("-n", "--nickname", type=str, default=None,
                        help="Select relay with the given nickname.")

    parser.add_argument("-a", "--address", type=str, default=None,
                        help="Select relays which contain the given (part "
                             "of an) IPv4 address.")

    return parser.parse_args()


def get_fingerprints(cached_consensus_path, exclude=[]):
    """
    Get all relay fingerprints in the provided consensus.

    Relay fingerprints which are present in the list `exclude' are ignored.
    """

    fingerprints = []

    for desc in stem.descriptor.parse_file(cached_consensus_path):
        if desc.fingerprint not in exclude:
            fingerprints.append(desc.fingerprint)

    return fingerprints


def get_exits(data_dir, country_code=None, bad_exit=False,
              version=None, nickname=None, address=None, hosts=[]):

    cached_consensus = {}
    have_exit_policy = {}
    have_exit_flag = {}

    cached_consensus_path = os.path.join(data_dir, "cached-consensus")
    cached_descriptors_path = os.path.join(data_dir, "cached-descriptors")

    # First, read the file "cached_descriptors" in order to get the full exit
    # policy of all relays instead of just the summary which might be
    # insufficient.

    try:
        for desc in stem.descriptor.parse_file(cached_descriptors_path):
            if desc.exit_policy.is_exiting_allowed():
                have_exit_policy[desc.fingerprint] = desc
    except IOError as err:
        logger.critical("File \"%s\" could not be read: %s" %
                        (cached_descriptors_path, err))
        sys.exit(1)

    exit_candidates = list(have_exit_policy.values())

    # Now, also read the file "cached_consensus" to see which relays got the
    # "Exit" flag from the directory authorities.

    try:
        for desc in stem.descriptor.parse_file(cached_consensus_path):
            cached_consensus[desc.fingerprint] = desc
            if stem.Flag.EXIT in desc.flags:
                have_exit_flag[desc.fingerprint] = desc
    except IOError as err:
        logger.critical("File \"%s\" could not be read: %s" %
                        (cached_descriptors_path, err))
        sys.exit(1)

    set_diff = set(have_exit_policy.keys()) - set(have_exit_flag.keys())
    logger.info("%d relays have non-empty exit policy but no exit flag." %
                len(set_diff))

    if hosts:
        def can_exit_to(desc):
            for (ip_addr, port) in hosts:

                # Use the full exit policy for the given descriptor.

                desc = have_exit_policy.get(desc.fingerprint, None)
                assert desc
                if not desc.exit_policy.can_exit_to(ip_addr, port):
                    return False

            return True

        exit_candidates = filter(can_exit_to, exit_candidates)

    if address:
        exit_candidates = filter(lambda desc: address == desc.address,
                                 exit_candidates)

    if nickname:
        exit_candidates = filter(lambda desc: nickname == desc.nickname,
                                 exit_candidates)

    if bad_exit:
        exit_candidates = filter(lambda desc: stem.Flag.BADEXIT in
                                 cached_consensus[desc.fingerprint].flags,
                                 exit_candidates)

    if country_code:
        exit_candidates = filter(lambda desc: ip2loc.resolve(desc.address) ==
                                 country_code, exit_candidates)

    if version:
        exit_candidates = filter(lambda desc: str(desc.tor_version) == version,
                                 exit_candidates)

    return (len(have_exit_policy),
            [desc.fingerprint for desc in exit_candidates])


def main():
    args = parse_cmd_args()

    _, exits = get_exits(args.data_dir, args.countrycode, args.badexit,
                         args.version, args.nickname, args.address)
    for e in exits:
        print("https://atlas.torproject.org/#details/%s" % e)


if __name__ == "__main__":
    sys.exit(main())
