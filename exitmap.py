#!/usr/bin/env python

import socket
import pkgutil
import argparse
from concurrent.futures import ProcessPoolExecutor

import stem
import stem.connection
import stem.process
import stem.descriptor
from stem.control import Controller, EventType

import log
import error
import const
import command
import circuitpool
import exitselector
import streamattacher

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

    args = parseCmdArgs()
    logger.debug("Command line arguments: %s" % str(args))

    # TODO: Start a Tor process here rather than connecting to an existing one.
    torCtrl = Controller.from_port(port = 10001)
    stem.connection.authenticate_none(torCtrl)

    for moduleName in args.module:
        probe(moduleName, args, torCtrl)

def probe( moduleName, args, torCtrl ):

    logger.info("Running module '%s'." % moduleName)
    module = __import__("modules.%s" % moduleName, fromlist=[moduleName])

    # Obtain the list of exit relays to scan.
    if args.exit:
        exitRelays = [args.exit]
    else:
        hosts = [(socket.gethostbyname(host), port) for
                 (host, port) in module.targets]
        exitRelays = exitselector.getExits(args.consensus,
                                           countryCode=args.country,
                                           hosts=hosts)

    count = len(exitRelays)
    if count < 1:
        raise error.ExitSelectionError("Exit selection yielded %d exits " \
                                       "but need at least one." % count)
    logger.info("About to probe %d exit relays." % count)

    # Create circuit pool and set up stream attacher.
    circuitPool = circuitpool.new(torCtrl, list(exitRelays))
    eventHandler = streamattacher.new(circuitPool, torCtrl)
    torCtrl.add_event_listener(eventHandler.newEvent, EventType.STREAM)

    circuits = torCtrl.get_circuits()
    logger.debug("Open circuits:")
    for circuit in circuits:
        logger.debug(circuit)

    executor = ProcessPoolExecutor(max_workers=const.CIRCUIT_POOL_SIZE)
    logger.debug("Beginning to populate process pool with %d jobs." % count)

    # Invoke a module instance for every exit relay.
    for _ in xrange(count, 0, -1):

        cmd = command.new(None)
        executor.submit(module.probe, cmd, count)
        count -= 1

    logger.info("Submitted jobs.  Terminating main scanner.")

if __name__ == "__main__":

    try:
        exit(main())
    except KeyboardInterrupt:
        logger.warning("Keyboard interrupt.")
        exit(1)
    finally:
        logger.info("Shutting down %s." % const.TOOL_NAME)
