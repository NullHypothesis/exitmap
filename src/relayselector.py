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
Extracts exit relays with given attributes from consensus.
"""

import os
import sys
import argparse
import logging

import stem
import stem.descriptor

import util

log = logging.getLogger(__name__)


def parse_cmd_args():
    """
    Parses and returns command line arguments.
    """

    parser = argparse.ArgumentParser(description="%s selects a subset of Tor "
                                     "exit relays." % sys.argv[0])

    parser.add_argument("-b", "--badexit", action="store_true", default=None,
                        help="Select bad exit relays.")

    parser.add_argument("-g", "--goodexit", action="store_true", default=None,
                        help="Select non-bad exit relays.")

    parser.add_argument("-c", "--countrycode", type=str, default=None,
                        help="Two-letter country code to select.")

    parser.add_argument("data_dir", metavar="DATA_DIR", type=str, default=None,
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


def get_exit_policies(cached_descriptors_path):
    """Read all relays' full exit policies from "cached_descriptors"."""

    try:
        have_exit_policy = {}

        # We don't validate to work around the following issue:
        # <https://gitweb.torproject.org/stem.git/commit/?id=ba8cee3>
        for desc in stem.descriptor.parse_file(cached_descriptors_path,
                                               validate=False):
            if desc.exit_policy.is_exiting_allowed():
                have_exit_policy[desc.fingerprint] = desc

        return have_exit_policy

    except IOError as err:
        log.critical("File \"%s\" could not be read: %s" %
                     (cached_descriptors_path, err))
        sys.exit(1)


def get_cached_consensus(cached_consensus_path):
    """Read relays' summarized descriptors from "cached_consensus"."""
    try:
        cached_consensus = {}
        for desc in stem.descriptor.parse_file(cached_consensus_path):
            cached_consensus[desc.fingerprint] = desc
        return cached_consensus

    except IOError as err:
        log.critical("File \"%s\" could not be read: %s" %
                     (cached_consensus_path, err))
        sys.exit(1)


def get_exits(data_dir,
              good_exit=True, bad_exit=False,
              version=None, nickname=None, address=None, country_code=None,
              requested_exits=None, destinations=None):
    """Load the Tor network consensus from DATA_DIR, and extract all exit
    relays that have the desired set of attributes.  Specifically:

     - requested_exits: If not None, must be a list of fingerprints,
       and only those relays will be included in the results.

     - country_code, version, nickname, address:
       If not None, only relays with the specified attributes
       will be included in the results.

     - bad_exit, good_exit: If True, the respective type of exit will
       be included.  At least one should be True, or else the results
       will be empty.

    These combine as follows:

           exit.fingerprint  IN requested_exits
       AND exit.country_code == country_code
       AND exit.version      == version
       AND exit.nickname     IN nickname
       AND exit.address      IN address
       AND (   (bad_exit AND exit.is_bad_exit)
            OR (good_exit AND NOT exit.is_bad_exit))

    In all cases, the criterion is skipped if the argument is None.

    Finally, 'destinations' is considered.  If this is None, all
    results from the above filter expression are returned.  Otherwise,
    'destinations' must be a set of (host, port) pairs, and only exits
    that will connect to *some* of these destinations will be included
    in the results.

    Returns a dictionary, whose keys are the selected relays' fingerprints.
    The value for each fingerprint is a set of (host, port) pairs that
    that exit is willing to connect to; this is always a subset of the
    input 'destinations' set.  (If 'destinations' was None, each value
    is a pseudo-set object for which '(host, port) in s' always
    returns True.)
    """


    cached_consensus_path = os.path.join(data_dir, "cached-consensus")
    cached_descriptors_path = os.path.join(data_dir, "cached-descriptors")

    cached_consensus = get_cached_consensus(cached_consensus_path)
    have_exit_policy = get_exit_policies(cached_descriptors_path)

    # Drop all exit relays which have a descriptor, but either did not
    # make it into the consensus at all, or are not marked as exits there.
    class StubDesc(object):
        def __init__(self):
            self.flags = frozenset()
    stub_desc = StubDesc()

    exit_candidates = [
        desc
        for fpr, desc in have_exit_policy.items()
        if stem.Flag.EXIT in cached_consensus.get(fpr, stub_desc).flags
    ]

    log.info("In addition to %d exit relays, %d relays have non-empty exit "
             "policy but no exit flag.", len(exit_candidates),
             len(have_exit_policy) - len(exit_candidates))
    if not exit_candidates:
        log.warning("No relays have both a non-empty exit policy and an exit "
                    "flag. This probably means the cached network consensus "
                    "is invalid.")
        return {}

    if bad_exit and good_exit:
        pass  # All exits are either bad or good.
    elif bad_exit:
        exit_candidates = [
            desc for desc in exit_candidates
            if stem.Flag.BADEXIT in cached_consensus[desc.fingerprint].flags
        ]
        if not exit_candidates:
            log.warning("There are no bad exits in the current consensus.")
            return {}
    elif good_exit:
        exit_candidates = [
            desc for desc in exit_candidates
            if stem.Flag.BADEXIT not in cached_consensus[desc.fingerprint].flags
        ]
        if not exit_candidates:
            log.warning("There are no good exits in the current consensus.")
            return {}
    else:
        # This was probably a programming error.
        log.warning("get_exits() called with bad_exits=False and "
                    "good_exits=False; this always returns zero exits")
        return {}

    # Filter conditions are checked from cheapest to most expensive.
    if address or nickname or version or requested_exits:
        exit_candidates = [
            desc for desc in exit_candidates
            if ((not address or address in desc.address) and
                (not nickname or nickname in desc.nickname) and
                (not version or version == str(desc.tor_version)) and
                (not requested_exits or desc.fingerprint in requested_exits))
        ]
    if not exit_candidates:
        log.warning("No exit relays meet basic filter conditions.")
        return {}

    if country_code:
        try:
            relay_fprs = frozenset(util.get_relays_in_country(country_code))
        except Exception as err:
            log.warning("get_relays_in_country() failed: %s" % err)
            relay_fprs = []

        exit_candidates = [
            desc for desc in exit_candidates
            if desc.fingerprint in relay_fprs
        ]
    if not exit_candidates:
        log.warning("No exit relays meet country-code filter condition.")
        return {}

    if not destinations:
        class UniversalSet(object):
            """A universal set contains everything, but cannot be enumerated.

            If the caller of get_exits does not specify destinations,
            its return value maps all fingerprints to a universal set,
            so that it can still fulfill the contract of returning a
            dictionary of the form { fingerprint : set(...) }.
            """
            def __nonzero__(self): return True

            def __contains__(self, obj): return True

            # __len__ is obliged to return a positive integer.
            def __len__(self): return sys.maxsize
        us = UniversalSet()
        exit_destinations = {
            desc.fingerprint: us for desc in exit_candidates}
    else:
        exit_destinations = {}
        for desc in exit_candidates:
            policy = have_exit_policy[desc.fingerprint].exit_policy
            ok_dests = frozenset(d for d in destinations
                                 if policy.can_exit_to(*d))
            if ok_dests:
                exit_destinations[desc.fingerprint] = ok_dests

    log.info("%d out of %d exit relays meet all filter conditions."
             % (len(exit_destinations), len(have_exit_policy)))
    return exit_destinations


def main():
    args = parse_cmd_args()

    exits = get_exits(args.data_dir,
                      country_code = args.countrycode,
                      bad_exit     = args.badexit,
                      good_exit    = args.goodexit,
                      version      = args.version,
                      nickname     = args.nickname,
                      address      = args.address)
    for e in exits.keys():
        print("https://atlas.torproject.org/#details/%s" % e)


if __name__ == "__main__":
    sys.exit(main())
