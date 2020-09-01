#!/usr/bin/env python3

# Copyright 2013-2016 Philipp Winter <phw@nymity.ch>
# Copyright 2016 Zack Weinberg <zackw@panix.com>
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
Module to measure round-trip times through an exit to various
destinations.  Each destination will receive ten TCP connections from
each scanned exit, no faster than one connection every 50ms.  The module
doesn't care whether it gets a SYN/ACK or a RST in response -- either
way, the round-trip time is recorded and the connection is dropped.

Connections are attempted to one of port 53, 22, 443 or 80, depending
on what's allowed by the exit's policy.

Until modules can take command-line arguments, the destinations should
be specified in a text file named "rtt-destinations.txt", one IP
address per line.  (You _may_ use hostnames, but if you do, they will
be resolved directly, not via Tor.)
"""

import sys
import os
import logging
import csv
import errno
import random
import socket
import util

# We don't _need_ the top-level exitmap module, but this is the most
# reliable way to figure out whether we need to add the directory with
# the utility modules that we _do_ need to sys.path.
try:
    import exitmap
except ImportError:
    current_path = os.path.dirname(__file__)
    src_path = os.path.abspath(os.path.join(current_path, ".."))
    sys.path.insert(0, src_path)
    import exitmap

try:
    from time import monotonic as tick
except ImportError:
    # FIXME: Maybe use ctypes to get at clock_gettime(CLOCK_MONOTONIC)?
    from time import time as tick

try:
    import selectors
except ImportError:
    import selectors34 as selectors

# Configuration parameters:
# The set of ports that we consider connecting to.
PREFERRED_PORT_ORDER = (53, 22, 443, 80)

# The total number of connections to make to each host.
CONNECTIONS_PER_HOST = 10

# The number of hosts to connect to in parallel.  Note that we will
# _not_ connect to any one host more than once at a time.
PARALLEL_CONNECTIONS = 4

# The delay between successive connections (seconds)
CONNECTION_SPACING = 0.25

# The per-connection timeout (seconds).
CONNECTION_TIMEOUT = 10.0


log = logging.getLogger(__name__)


def progress(total, pending, complete):
    log.info("{:>6}/{:>6} complete, {} pending"
             .format(complete, total, pending))


def perform_probes(addresses, spacing, parallel, timeout, wr):
    """Make a TCP connection to each of the ADDRESSES, in order, and
    measure the time for connect(2) to either succeed or fail -- we
    don't care which.  Each element of the iterable ADDRESSES should
    be an AF_INET address 2-tuple (i.e. ('a.b.c.d', n)).  Successive
    connections will be no closer to each other in time than SPACING
    floating-point seconds.  No more than PARALLEL concurrent
    connections will occur at any one time.  Sockets that have neither
    succeeded nor failed to connect after TIMEOUT floating-point
    seconds will be treated as having failed.  No data is transmitted;
    each socket is closed immediately after the connection resolves.

    The results are written to the csv.writer object WR; each row of the
    file will be <ipaddr>,<port>,<elapsed time>.
    """

    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if spacing <= 0:
        raise ValueError("spacing must be positive")
    if parallel < 1:
        raise ValueError("parallel must be at least 1")

    sel = selectors.DefaultSelector()
    EVENT_READ = selectors.EVENT_READ
    AF_INET = socket.AF_INET
    SOCK_STREAM = socket.SOCK_STREAM

    EINPROGRESS = errno.EINPROGRESS
    CONN_RESOLVED = (0,
                     errno.ECONNREFUSED,
                     errno.EHOSTUNREACH,
                     errno.ENETUNREACH,
                     errno.ETIMEDOUT,
                     errno.ECONNRESET)

    pending = set()
    addresses.reverse()
    last_connection = 0
    last_progress = 0
    total = len(addresses)
    complete = 0
    change = False

    try:
        while pending or addresses:
            now = tick()
            if change or now - last_progress > 10:
                progress(total, len(pending), complete)
                last_progress = now
                change = False

            if (len(pending) < parallel and addresses
                and now - last_connection >= spacing):

                addr = addresses.pop()
                sock = socket.socket(AF_INET, SOCK_STREAM)
                sock.setblocking(False)

                last_connection = tick()
                err = sock.connect_ex(addr)
                log.debug("Socket %d connecting to %r returned %d/%s",
                          sock.fileno(), addr, err, os.strerror(err))
                if err == EINPROGRESS:
                    # This is the expected case: the connection attempt is
                    # in progress and we must wait for results.
                    pending.add(sel.register(sock, EVENT_READ,
                                             (addr, last_connection)))
                    change = True

                elif err in CONN_RESOLVED:
                    # The connection attempt resolved before connect()
                    # returned.
                    after = tick()
                    sock.close()
                    wr.writerow((addr[0], addr[1], after - now))
                    complete += 1
                    change = True

                else:
                    # Something dire has happened and we probably
                    # can't continue (for instance, there's no local
                    # network connection).
                    exc = socket.error(err, os.strerror(err))
                    exc.filename = '%s:%d' % addr
                    raise exc

            events = sel.select(spacing)
            after = tick()
            # We don't care whether each connection succeeded or failed.
            for key, _ in events:
                addr, before = key.data
                sock = key.fileobj
                log.debug("Socket %d connecting to %r resolved",
                          sock.fileno(), addr)

                sel.unregister(sock)
                sock.close()
                pending.remove(key)
                wr.writerow((addr[0], addr[1], after - before))
                complete += 1
                change = True

            # Check for timeouts.
            for key in list(pending):
                addr, before = key.data
                if after - before >= timeout:
                    sock = key.fileobj
                    log.debug("Socket %d connecting to %r timed out",
                              sock.fileno(), addr)
                    sel.unregister(sock)
                    sock.close()
                    pending.remove(key)
                    wr.writerow((addr[0], addr[1], after - before))
                    complete += 1
                    change = True

        # end while
        progress(total, len(pending), complete)

    finally:
        for key in pending:
            sel.unregister(key.fileobj)
            key.fileobj.close()
        sel.close()


def choose_probe_order(dests):
    """Choose a randomized probe order for the destinations DESTS, which is
       a set of (host, port) pairs.  The return value is a list acceptable
       as the ADDRESSES argument to perform_probes."""

    hosts = {}
    for h, p in dests:
        if h not in hosts: hosts[h] = set()
        hosts[h].add(p)

    remaining = {}
    last_appearance = {}
    full_address = {}
    for host, usable_ports in hosts.items():
        for p in PREFERRED_PORT_ORDER:
            if p in usable_ports:
                full_address[host] = (host, p)
                remaining[host] = CONNECTIONS_PER_HOST
                last_appearance[host] = -1

    rv = []
    deadcycles = 0
    while remaining:
        ks = list(remaining.keys())
        x = random.choice(ks)
        last = last_appearance[x]
        if last == -1 or (len(rv) - last) >= (len(ks) // 4):
            last_appearance[x] = len(rv)
            rv.append(full_address[x])
            remaining[x] -= 1
            if not remaining[x]:
                del remaining[x]
            deadcycles = 0
        else:
            deadcycles += 1
            if deadcycles == 10:
                raise RuntimeError("choose_probe_order: 10 dead cycles\n"
                                   "remaining: %r\n"
                                   "last_appearance: %r\n"
                                   % (remaining, last_appearance))
    return rv


def probe(exit_desc, run_python_over_tor, run_cmd_over_tor,
          destinations, **kwargs):
    """
    Probe the given exit relay.
    """
    addresses = choose_probe_order(destinations)

    try:
        os.makedirs(util.analysis_dir)
    except OSError as err:
        if err.errno != errno.EEXIST:
            raise

    with open(os.path.join(util.analysis_dir,
                           exit_desc.fingerprint + ".csv"), "wt") as f:
        wr = csv.writer(f, quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
        wr.writerow(("host", "port", "elapsed"))

        run_python_over_tor(perform_probes,
                            addresses,
                            CONNECTION_SPACING,
                            PARALLEL_CONNECTIONS,
                            CONNECTION_TIMEOUT,
                            wr)

# exitmap needs this variable to figure out which relays can exit to the given
# destination(s).

destinations = None


def setup():
    ds = set()
    with open("rtt-destinations.txt") as f:
        for line in f:
            line = line.strip()
            if not line or line[0] == '#': continue
            ipaddr = socket.getaddrinfo(
                line, 80, socket.AF_INET, socket.SOCK_STREAM, 0, 0)[0][4][0]

            for p in PREFERRED_PORT_ORDER:
                ds.add((ipaddr, p))

    global destinations
    destinations = sorted(ds)
