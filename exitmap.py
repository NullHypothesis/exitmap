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
import time
import socket
import pkgutil
import argparse
import datetime
import random

import stem
import stem.connection
import stem.process
import stem.descriptor
from stem.control import Controller, EventType

import log
import error
import const
import exitselector

from eventhandler import EventHandler
from stats import Statistics

logger = log.get_logger()


def bootstrap_tor():
    """
    Invoke a Tor process which is subsequently used by exitmap.
    """

    logger.debug("Attempting to invoke Tor process in directory \"%s\"." %
                 const.TOR_DATA_DIRECTORY)

    proc = stem.process.launch_tor_with_config(
        config={
            "SOCKSPort": str(const.TOR_SOCKS_PORT),
            "ControlPort": str(const.TOR_CONTROL_PORT),
            "DataDirectory": const.TOR_DATA_DIRECTORY,
            "LearnCircuitBuildTimeout": "0",
            "CircuitBuildTimeout": "40",
            "__DisablePredictedCircuits": "1",
            "__LeaveStreamsUnattached": "1",
            "FetchHidServDescriptors": "0",
            "UseMicroDescriptors": "0",
        },
        timeout=30,
        take_ownership=True,
        completion_percent=80,
        init_msg_handler=lambda line: logger.debug("Tor says: %s" % line),
    )

    logger.info("Successfully started Tor process (PID=%d)." % proc.pid)

    return proc


def parse_cmd_args():
    """
    Parses and returns command line arguments.
    """

    parser = argparse.ArgumentParser(description="Monitors and probes Tor "
                                     "exit relays.")

    group = parser.add_mutually_exclusive_group()

    group.add_argument("-C", "--country", type=str, default=None,
                       help="Only probe exit relays in the given country.")

    group.add_argument("-e", "--exit", type=str, default=None,
                       help="Only probe the exit relay having the given "
                            "fingerprint.")

    parser.add_argument("-c", "--consensus", type=str, default="",
                        help="Path to a Tor network consensus.")

    parser.add_argument("module", nargs='+',
                        help="Run the given module (available: %s)." %
                        ", ".join(list_modules()))

    return parser.parse_args()


def list_modules():
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
    args = parse_cmd_args()
    logger.debug("Command line arguments: %s" % str(args))

    bootstrap_tor()
    controller = Controller.from_port(port=const.TOR_CONTROL_PORT)
    stem.connection.authenticate_none(controller)

    # Redirect Tor's logging to work around the following problem:
    # https://bugs.torproject.org/9862

    logger.debug("Redirecting Tor's logging to /dev/null.")
    controller.set_conf("Log", "err file /dev/null")

    # We already have the current consensus, so we don't need additional
    # descriptors or the streams fetching them.

    controller.set_conf("FetchServerDescriptors", "0")

    for module_name in args.module:
        run_module(module_name, args, controller, stats)

    return 0


def select_exits(args, module):
    """
    Based on the module's intended destinations, select exit relays to probe.

    Exit relays are selected for probing if their exit policy allows exiting to
    the module's intended destinations.
    """

    before = datetime.datetime.now()
    hosts = []

    # If no consensus was given over the command line, we take the one in the
    # data directory.

    if args.consensus:
        consensus = args.consensus
    else:
        consensus = const.TOR_DATA_DIRECTORY + "cached-consensus"

    if not os.path.exists(consensus):
        logger.error("The consensus \"%s\" does not exist." % consensus)
        exit(1)

    if module.destinations is not None:
        hosts = [(socket.gethostbyname(host), port) for
                 (host, port) in module.destinations]

    # '-e' was used to specify a single exit relay.

    if args.exit:
        exit_relays = [args.exit]
        total = len(exit_relays)
    else:
        total, exit_relays = exitselector.get_exits(consensus,
                                                    country_code=args.country,
                                                    hosts=hosts)

    logger.debug("Successfully selected exit relays after %s." %
                 str(datetime.datetime.now() - before))

    logger.info("%d%s exits out of all %s exit relays allow exiting to %s." %
                (len(exit_relays), " %s" % args.country if args.country else "",
                 total, hosts))

    assert isinstance(exit_relays, list)

    random.shuffle(exit_relays)

    return exit_relays


def run_module(module_name, args, controller, stats):
    logger.info("Running module '%s'." % module_name)
    module = __import__("modules.%s" % module_name, fromlist=[module_name])

    exit_relays = select_exits(args, module)

    count = len(exit_relays)
    stats.total_circuits += count

    if count < 1:
        raise error.ExitSelectionError("Exit selection yielded %d exits "
                                       "but need at least one." % count)

    handler = EventHandler(controller, module.probe, stats)
    controller.add_event_listener(handler.new_event,
                                  EventType.CIRC, EventType.STREAM)

    logger.debug("Circuit creation delay of %.3f seconds will account for "
                 "total delay of %.3f seconds." % (
                     const.CIRCUIT_BUILD_DELAY,
                     count * const.CIRCUIT_BUILD_DELAY))

    # Start building a circuit for every exit relay we got.

    before = datetime.datetime.now()
    logger.debug("Beginning to trigger %d circuit creation(s)." % count)

    for exit_relay in exit_relays:
        try:
            controller.new_circuit([const.FIRST_HOP, exit_relay])
        except stem.ControllerError as err:
            stats.failed_circuits += 1
            logger.warning("Circuit with exit relay \"%s\" could not be "
                           "created: %s" % (exit_relay, err))

        time.sleep(const.CIRCUIT_BUILD_DELAY)

    logger.debug("Done triggering circuit creations after %s." %
                 str(datetime.datetime.now() - before))

    stats.modules_run += 1


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        logger.info("Caught keyboard interrupt.")
