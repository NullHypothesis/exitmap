#!/usr/bin/env python

import sys
import argparse

import stem.descriptor

import ip2loc

def parseCmdArgs():
    """
    Parses and returns command line arguments.
    """

    parser = argparse.ArgumentParser(description="%s selects a subset of Tor "
                                     "exit relays." % sys.argv[0])

    parser.add_argument("-b", "--badexit", action="store_true",
                        help="Select bad exit relays.")

    parser.add_argument("-c", "--countrycode", type=str, default=None,
                        help="Two-letter country code to select.")

    parser.add_argument("-d", "--consensus", type=str, default=None,
                        help="Consensus document containing relays.")

    parser.add_argument("-v", "--version", type=str, default=None,
                        help="Show relays with a specific version.")

    return parser.parse_args()

def getExits( consensus, countryCode=None, badExit=False,
              version=None, hosts=[] ):

    exits = []

    if not consensus:
        return []

    for desc in stem.descriptor.parse_file(open(consensus)):

        # We are only interested in exit relays.
        if not "Exit" in desc.flags:
            continue

        a = b = c = False

        for (ip, port) in hosts:
            if not desc.exit_policy.can_exit_to(ip, port):
                continue

        if (badExit and ("BadExit" in desc.flags)) or (not badExit):
            a = True

        if ((countryCode is not None) and \
            (ip2loc.resolve(desc.address) == countryCode)) or \
           (countryCode == None):
            b = True

        if (version and (str(desc.version) == version)) or (not version):
            c = True

        if a and b and c:
            exits.append(desc.fingerprint)

    return exits

def main():

    args = parseCmdArgs()

    exits = getExits(args.consensus, args.countrycode, args.badexit,
                     args.version)
    for e in exits:
        print("https://atlas.torproject.org/#details/%s" % e)

if __name__ == "__main__":
    sys.exit(main())
