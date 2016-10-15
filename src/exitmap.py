# Copyright 2013-2016 Philipp Winter <phw@nymity.ch>
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
Performs a task over (a subset of) all Tor exit relays.
"""

import sys
import os
import time
import socket
import pkgutil
import argparse
import datetime
import random
import logging
import ConfigParser
import functools
import pwd

import stem
import stem.connection
import stem.process
import stem.descriptor
from stem.control import Controller, EventType

import modules
import error
import util
import relayselector

from eventhandler import EventHandler
from stats import Statistics

log = logging.getLogger(__name__)


def bootstrap_tor(args):
    """
    Invoke a Tor process which is subsequently used by exitmap.
    """

    log.info("Attempting to invoke Tor process in directory \"%s\".  This "
             "might take a while." % args.tor_dir)

    if not args.first_hop:
        log.info("No first hop given.  Using randomly determined first "
                 "hops for circuits.")

    ports = {}
    partial_parse_log_lines = functools.partial(util.parse_log_lines, ports)

    try:
        proc = stem.process.launch_tor_with_config(
            config={
                "SOCKSPort": "auto",
                "ControlPort": "auto",
                "DataDirectory": args.tor_dir,
                "CookieAuthentication": "1",
                "LearnCircuitBuildTimeout": "0",
                "CircuitBuildTimeout": "40",
                "__DisablePredictedCircuits": "1",
                "__LeaveStreamsUnattached": "1",
                "FetchHidServDescriptors": "0",
                "UseMicroDescriptors": "0",
                "PathsNeededToBuildCircuits": "0.95",
            },
            timeout=300,
            take_ownership=True,
            completion_percent=80,
            init_msg_handler=partial_parse_log_lines,
        )
        log.info("Successfully started Tor process (PID=%d)." % proc.pid)
    except OSError as err:
        log.error("Couldn't launch Tor: %s.  Maybe try again?" % err)
        sys.exit(1)

    return ports["socks"], ports["control"]


def parse_cmd_args():
    """
    Parse and return command line arguments.
    """

    desc = "Perform a task over (a subset of) all Tor exit relays."
    parser = argparse.ArgumentParser(description=desc, add_help=False)

    parser.add_argument("-f", "--config-file", type=str, default=None,
                        help="Path to the configuration file.")

    args, remaining_argv = parser.parse_known_args()

    # First, try to load the configuration file and load its content as our
    # defaults.

    if args.config_file:
        config_file = args.config_file
    else:
        home_dir = os.path.expanduser("~")
        config_file = os.path.join(home_dir, ".exitmaprc")

    config_parser = ConfigParser.SafeConfigParser()
    file_parsed = config_parser.read([config_file])
    if file_parsed:
        try:
            defaults = dict(config_parser.items("Defaults"))
        except ConfigParser.NoSectionError as err:
            log.warning("Could not parse config file \"%s\": %s" %
                        (config_file, err))
            defaults = {}
    else:
        defaults = {}

    parser = argparse.ArgumentParser(parents=[parser])
    parser.set_defaults(**defaults)

    # Now, load the arguments given over the command line.

    group = parser.add_mutually_exclusive_group()

    group.add_argument("-C", "--country", type=str, default=None,
                       help="Only probe exit relays of the country which is "
                            "determined by the given 2-letter country code.")

    group.add_argument("-e", "--exit", type=str, default=None,
                       help="Only probe the exit relay which has the given "
                            "20-byte fingerprint.")

    group.add_argument("-E", "--exit-file", type=str, default=None,
                       help="File containing the 20-byte fingerprints "
                            "of exit relays to probe, one per line.")

    parser.add_argument("-d", "--build-delay", type=float, default=3,
                        help="Wait for the given delay (in seconds) between "
                             "circuit builds.  The default is 3.")

    parser.add_argument("-n", "--delay-noise", type=float, default=0,
                        help="Sample random value in [0, DELAY_NOISE) and "
                             "randomly add it to or subtract it from the build"
                             " delay.  This randomises the build delay.  The "
                             "default is 0.")

    # Create /tmp/exitmap_tor_datadir-$USER to allow many users to run
    # exitmap in parallel.

    tor_directory = "/tmp/exitmap_tor_datadir-" + pwd.getpwuid(os.getuid())[0]

    parser.add_argument("-t", "--tor-dir", type=str,
                        default=tor_directory,
                        help="Tor's data directory.  If set, the network "
                             "consensus can be re-used in between scans which "
                             "speeds up bootstrapping.  The default is %s." %
                             tor_directory)

    parser.add_argument("-a", "--analysis-dir", type=str,
                        default=None,
                        help="The directory where analysis results are "
                             "written to.  If the directory is used depends "
                             "on the module.  The default is /tmp.")

    parser.add_argument("-v", "--verbosity", type=str, default="info",
                        help="Minimum verbosity level for logging.  Available "
                             "in ascending order: debug, info, warning, "
                             "error, critical).  The default is info.")

    parser.add_argument("-i", "--first-hop", type=str, default=None,
                        help="The 20-byte fingerprint of the Tor relay which "
                             "is used as first hop.  This relay should be "
                             "under your control.")

    parser.add_argument("-o", "--logfile", type=str, default=None,
                        help="Filename to which log output should be written "
                             "to.")

    exits = parser.add_mutually_exclusive_group()

    exits.add_argument("-b", "--bad-exits", action="store_true",
                       help="Only scan exit relays that have the BadExit "
                            "flag.  By default, only good exits are scanned.")

    exits.add_argument("-l", "--all-exits", action="store_true",
                       help="Scan all exits, including those that have the "
                            "BadExit flag.  By default, only good exits are "
                            "scanned.")

    parser.add_argument("-V", "--version", action="version",
                        version="%(prog)s 2015.04.06")

    parser.add_argument("module", nargs='+',
                        help="Run the given module (available: %s)." %
                        ", ".join(get_modules()))

    parser.set_defaults(**defaults)

    return parser.parse_args(remaining_argv)


def get_modules():
    """
    Return all modules located in "modules/".
    """

    modules_path = os.path.dirname(modules.__file__)

    return [name for _, name, _ in pkgutil.iter_modules([modules_path])]


def main():
    """
    The scanner's entry point.
    """

    stats = Statistics()
    args = parse_cmd_args()

    # Create and set the given directories.

    if args.tor_dir and not os.path.exists(args.tor_dir):
        os.makedirs(args.tor_dir)

    logging.getLogger("stem").setLevel(logging.__dict__[args.verbosity.upper()])
    log_format = "%(asctime)s %(name)s [%(levelname)s] %(message)s"
    logging.basicConfig(format=log_format,
                        level=logging.__dict__[args.verbosity.upper()],
                        filename=args.logfile)

    log.debug("Command line arguments: %s" % str(args))

    socks_port, control_port = bootstrap_tor(args)
    controller = Controller.from_port(port=control_port)
    stem.connection.authenticate(controller)

    # Redirect Tor's logging to work around the following problem:
    # https://bugs.torproject.org/9862

    log.debug("Redirecting Tor's logging to /dev/null.")
    controller.set_conf("Log", "err file /dev/null")

    # We already have the current consensus, so we don't need additional
    # descriptors or the streams fetching them.

    controller.set_conf("FetchServerDescriptors", "0")

    cached_consensus_path = os.path.join(args.tor_dir, "cached-consensus")
    if args.first_hop and (not util.relay_in_consensus(args.first_hop,
                                                       cached_consensus_path)):
        log.critical("Given first hop \"%s\" not found in consensus.  Is it"
                     " offline?" % args.first_hop)
        return 1

    for module_name in args.module:

        if args.analysis_dir is not None:
            datestr = time.strftime("%Y-%m-%d_%H:%M:%S%z") + "_" + module_name
            util.analysis_dir = os.path.join(args.analysis_dir, datestr)

        try:
            run_module(module_name, args, controller, socks_port, stats)
        except error.ExitSelectionError as err:
            log.error("Failed to run because : %s" % err)
    return 0


def lookup_destinations(module):
    """
    Determine the set of destinations that the module might like to scan.
    This removes redundancies and reduces all hostnames to IP addresses.
    """
    destinations = set()
    addrs = {}
    if hasattr(module, 'destinations'):
        raw_destinations = module.destinations
        if raw_destinations is not None:
            for (host, port) in raw_destinations:
                if host not in addrs:
                    addrs[host] = socket.gethostbyname(host)
                destinations.add((addrs[host], port))

    return destinations


def select_exits(args, module):
    """
    Select exit relays which allow exiting to the module's scan destinations.

    We select exit relays based on their published exit policy.  In particular,
    we check if the exit relay's exit policy specifies that we can connect to
    our intended destination(s).
    """

    before = datetime.datetime.now()
    destinations = lookup_destinations(module)

    if args.exit:
        # '-e' was used to specify a single exit relay.
        requested_exits = [args.exit]
    elif args.exit_file:
        # '-E' was used to specify a file containing exit relays.
        try:
            requested_exits = [line.strip() for line in open(args.exit_file)]
        except OSError as err:
            log.error("Could not read %s: %s", args.exit_file, err.strerror)
            sys.exit(1)
        except Exception as err:
            log.error("Could not read %s: %s", args.exit_file, err)
            sys.exit(1)
    else:
        requested_exits = None

    exit_destinations = relayselector.get_exits(
        args.tor_dir,
        good_exit       = args.all_exits or (not args.bad_exits),
        bad_exit        = args.all_exits or args.bad_exits,
        country_code    = args.country,
        requested_exits = requested_exits,
        destinations    = destinations)

    log.debug("Successfully selected exit relays after %s." %
              str(datetime.datetime.now() - before))

    return exit_destinations


def run_module(module_name, args, controller, socks_port, stats):
    """
    Run an exitmap module over all available exit relays.
    """

    log.info("Running module '%s'." % module_name)
    stats.modules_run += 1

    try:
        module = __import__("modules.%s" % module_name, fromlist=[module_name])
    except ImportError as err:
        log.error("Failed to load module because: %s" % err)
        return

    # Let module perform one-off setup tasks.

    if hasattr(module, "setup"):
        log.debug("Calling module's setup() function.")
        module.setup()

    exit_destinations = select_exits(args, module)

    exit_relays = list(exit_destinations.keys())
    random.shuffle(exit_relays)

    count = len(exit_relays)
    stats.total_circuits += count

    if count < 1:
        raise error.ExitSelectionError("Exit selection yielded %d exits "
                                       "but need at least one." % count)

    handler = EventHandler(controller, module, socks_port, stats,
                           exit_destinations=exit_destinations)

    controller.add_event_listener(handler.new_event,
                                  EventType.CIRC, EventType.STREAM)

    duration = count * args.build_delay
    log.info("Scan is estimated to take around %s." %
             datetime.timedelta(seconds=duration))

    log.info("Beginning to trigger %d circuit creation(s)." % count)

    iter_exit_relays(exit_relays, controller, stats, args)


def sleep(delay, delay_noise):
    """
    Sleep in between circuit creations.

    This has two purposes.  First, it spreads the load on both the Tor network
    and our scanning destination over time.  Second, by using random values to
    obscure our circuit creation patterns, we hopefully make it harder for a
    vigilant adversary to detect our scanning.
    """

    noise = 0
    if delay_noise != 0:
        noise = random.random() * delay_noise
        if random.randint(0, 1):
            noise = -noise

    delay += noise
    if delay < 0:
        delay = 0

    log.debug("Sleeping for %.1fs, then building next circuit." % delay)
    time.sleep(delay)


def iter_exit_relays(exit_relays, controller, stats, args):
    """
    Invoke circuits for all selected exit relays.
    """

    before = datetime.datetime.now()
    cached_consensus_path = os.path.join(args.tor_dir, "cached-consensus")
    fingerprints = relayselector.get_fingerprints(cached_consensus_path)
    count = len(exit_relays)

    # Start building a circuit for every exit relay we got.

    for i, exit_relay in enumerate(exit_relays):

        # Determine the hops in our next circuit.

        if args.first_hop:
            hops = [args.first_hop, exit_relay]
        else:
            all_hops = list(fingerprints)

            try:
                all_hops.remove(exit_relay)
            except ValueError:
                # Catch exception when exit is not in the cached_consensus
                pass
            first_hop = random.choice(all_hops)
            log.debug("Using random first hop %s for circuit." % first_hop)
            hops = [first_hop, exit_relay]

        assert len(hops) > 1

        try:
            controller.new_circuit(hops)
        except stem.ControllerError as err:
            stats.failed_circuits += 1
            log.debug("Circuit with exit relay \"%s\" could not be "
                      "created: %s" % (exit_relay, err))

        if i != (count - 1):
            sleep(args.build_delay, args.delay_noise)

    log.info("Done triggering circuit creations after %s." %
             str(datetime.datetime.now() - before))
