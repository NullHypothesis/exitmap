#!/usr/bin/env python

import time
import socket
import pkgutil
import argparse
import datetime

import stem
import stem.connection
import stem.process
import stem.descriptor
from stem.control import Controller, EventType

import log
import error
import const
import command
import exitselector

from eventhandler import EventHandler
from stats import Statistics

logger = log.getLogger()

def parseCmdArgs():
    """
    Parses and returns command line arguments.
    """

    parser = argparse.ArgumentParser(description="Monitors and probes Tor " \
                                     "exit relays.")

    group = parser.add_mutually_exclusive_group()

    group.add_argument("-C", "--country", type=str, default=None,
                       help="Only probe exit relays in the given country.")

    group.add_argument("-e", "--exit", type=str, default=None,
                       help="Only probe the exit relay having the given " \
                            "fingerprint.")

    parser.add_argument("-c", "--consensus", type=str, default="",
                        help="Path to a Tor network consensus.")

    parser.add_argument("module", nargs='+',
                        help="Run the given module (available: %s)." %
                        ", ".join(listModules()))

    return parser.parse_args()

def listModules():
    """
    List all available modules located in "modules/".
    """

    modules = []

    for _, name, _ in pkgutil.iter_modules(["modules"]):
        modules.append(name)

    return modules

def main():
    """
    The scanner's entry point.
    """

    stats = Statistics()
    args = parseCmdArgs()
    logger.debug("Command line arguments: %s" % str(args))

    # TODO: Start a Tor process here rather than connecting to an existing one.
    torCtrl = Controller.from_port(port = 10001)
    stem.connection.authenticate_none(torCtrl)

    for moduleName in args.module:
        runModule(moduleName, args, torCtrl, stats)

def selectExits( args, module ):
    """
    Based on the module's intended destinations, select exit relays to probe.

    Exit relays are selected for probing if their exit policy allows exiting to
    the module's intended destinations.
    """

    before = datetime.datetime.now()
    hosts = []

    if module.destinations is not None:
        hosts = [(socket.gethostbyname(host), port) for
                 (host, port) in module.destinations]

    # '-e' was used to specify a single exit relay.
    if args.exit:
        exitRelays = [args.exit]
        total = len(exitRelays)
    else:
        total, exitRelays = exitselector.getExits(args.consensus,
                                                  countryCode=args.country,
                                                  hosts=hosts)

    logger.debug("Successfully selected exit relays after %s." %
                 str(datetime.datetime.now() - before))
    logger.info("%d%s exits out of all %s exit relays allow exiting to %s." %
                (len(exitRelays), " %s" % args.country if args.country else "",
                 total, hosts))

    assert isinstance(exitRelays, list)

    return exitRelays

def runModule( moduleName, args, torCtrl, stats ):

    logger.info("Running module '%s'." % moduleName)
    module = __import__("modules.%s" % moduleName, fromlist=[moduleName])

    exitRelays = selectExits(args, module)

    count = len(exitRelays)
    stats.totalCircuits += count
    if count < 1:
        raise error.ExitSelectionError("Exit selection yielded %d exits " \
                                       "but need at least one." % count)

    handler = EventHandler(torCtrl, module.probe, stats)
    torCtrl.add_event_listener(handler.newEvent,
                               EventType.CIRC, EventType.STREAM)

    logger.debug("Circuit creation delay of %.3f seconds will account for " \
                 "total delay of %.3f seconds." % (const.CIRCUIT_BUILD_DELAY,
                 count * const.CIRCUIT_BUILD_DELAY))

    # Start building a circuit for every exit relay we got.
    before = datetime.datetime.now()
    logger.debug("Beginning to trigger %d circuit creation(s)." % count)
    for exitRelay in exitRelays:
        try:
            torCtrl.new_circuit([const.FIRST_HOP, exitRelay])
        except stem.ControllerError as err:
            stats.failedCircuits += 1
            logger.warning("Circuit with exit relay \"%s\" could not be " \
                           "created: %s" % (exitRelay, err))
        time.sleep(const.CIRCUIT_BUILD_DELAY)

    logger.debug("Done triggering circuit creations after %s." %
                 str(datetime.datetime.now() - before))
    stats.modulesRun += 1

if __name__ == "__main__":

    try:
        exit(main())
    except KeyboardInterrupt:
        logger.info("Caught keyboard interrupt.")
