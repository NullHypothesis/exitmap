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

import sys
import argparse

import stem
import stem.descriptor

import ip2loc


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

    parser.add_argument("-d", "--consensus", type=str, default=None,
                        help="Consensus document containing relays.")

    parser.add_argument("-v", "--version", type=str, default=None,
                        help="Show relays with a specific version.")

    parser.add_argument("-n", "--nickname", type=str, default=None,
                        help="Select relay with the given nickname.")

    parser.add_argument("-a", "--address", type=str, default=None,
                        help="Select relays which contain the given (part "
                             "of an) IPv4 address.")

    return parser.parse_args()


def get_exits(consensus, country_code=None, bad_exit=False,
              version=None, nickname=None, address=None, hosts=[]):

    all_exits = [desc for desc in stem.descriptor.parse_file(consensus) if stem.Flag.EXIT in desc.flags]
    exits = list(all_exits)  # exits that match our given criteria

    if hosts:
        def can_exit_to(desc):
            for (ip, port) in hosts:
                if desc.exit_policy.can_exit_to(ip, port):
                    return True

            return False

        exits = filter(can_exit_to, exits)

    if address:
        exits = filter(lambda desc: address == desc.address, exits)

    if nickname:
        exits = filter(lambda desc: nickname == desc.nickname, exits)

    if bad_exit:
        exits = filter(lambda desc: stem.Flag.BADEXIT in desc.flags, exits)

    if country_code:
        exits = filter(lambda desc: ip2loc.resolve(desc.address) == country_code, exits)

    if version:
        exits = filter(lambda desc: str(desc.version) == version, exits)

    return (len(all_exits), [desc.fingerprint for desc in exits])


def main():
    args = parse_cmd_args()

    _, exits = get_exits(args.consensus, args.countrycode, args.badexit,
                         args.version, args.nickname, args.address)
    for e in exits:
        print("https://atlas.torproject.org/#details/%s" % e)


if __name__ == "__main__":
    sys.exit(main())
