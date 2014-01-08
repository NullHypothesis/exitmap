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

    parser.add_argument("-n", "--nickname", type=str, default=None,
                        help="Select relay with the given nickname.")

    return parser.parse_args()

def getExits( consensus, countryCode=None, badExit=False,
              version=None, nickname=None, hosts=[] ):

    exits = []
    total = 0

    if not consensus:
        return []

    for desc in stem.descriptor.parse_file(open(consensus)):

        # We are only interested in exit relays.
        if not "Exit" in desc.flags:
            continue

        total += 1

        cannotExit = False
        for (ip, port) in hosts:
            if not desc.exit_policy.can_exit_to(ip, port):
                cannotExit = True
                break
        if cannotExit:
            continue

        if not ((nickname and nickname in desc.nickname) or (not nickname)):
            continue

        if not ((badExit and ("BadExit" in desc.flags)) or (not badExit)):
            continue

        if not (((countryCode is not None) and \
            (ip2loc.resolve(desc.address) == countryCode)) or \
           (countryCode == None)):
            continue

        if not ((version and (str(desc.version) == version)) or (not version)):
            continue

        exits.append(desc.fingerprint)

    return (total, exits)

def main():

    args = parseCmdArgs()

    _, exits = getExits(args.consensus, args.countrycode, args.badexit,
                        args.version, args.nickname)
    for e in exits:
        print("https://atlas.torproject.org/#details/%s" % e)

if __name__ == "__main__":
    sys.exit(main())
