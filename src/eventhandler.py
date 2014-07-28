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

import functools
import threading
import multiprocessing
import socket
import sys

import stem
from stem import StreamStatus
from stem import CircStatus

import command
import mysocks
import util
import log

logger = log.get_logger()


def func(queue, circ_event_id, module, exit_fpr):

    orig_socket = socket.socket
    mysocks.setdefaultproxy(mysocks.PROXY_TYPE_SOCKS5, "127.0.0.1", 45678)

    # Prepare the execution environment.  In particular, a Command() object
    # to execute external tools and a decorator for the probing module we
    # are about to run.

    cmd = command.Command("/tmp/torsocks.conf", queue, circ_event_id,
                          orig_socket)

    # Monkey-patch the socket API to redirect network traffic originating
    # from our Python process to Tor's SOCKS port.

    socket.socket = mysocks.socksocket
    mysocks.setqueue(queue, circ_event_id)

    try:
        module(exit_fpr, cmd)
        socket.socket = orig_socket

        logger.debug("Informing event handler that module finished.")
        queue.put((None, None))

    except KeyboardInterrupt:
        pass


class EventHandler(object):
    """
    Implement a handler for asynchronous Tor events.

    The handler processes only stream and circuit events.  New streams are
    attached to their corresponding circuits since exitmap's Tor process leaves
    new streams unattached.
    """

    def __init__(self, controller, probing_module, stats):
        """
        Initialise an EventHandler object.
        """

        self.stats = stats
        self.attachers = {}
        self.controller = controller
        self.probing_module = probing_module
        self.origsock = socket.socket
        self.manager = multiprocessing.Manager()
        self.queue = self.manager.Queue()
        self.pool = multiprocessing.Pool()

        queue_threaed = threading.Thread(target=self.queue_reader)
        queue_threaed.daemon = False
        queue_threaed.start()

        mysocks.setdefaultproxy(mysocks.PROXY_TYPE_SOCKS5, "127.0.0.1", 45678)

    def prepare_attach(self, port, circuit_id = None, stream_id = None):
        """
        Prepare for attaching a stream to a circuit.

        If we already have the corresponding stream/circuit, it can be attached
        right now.  Otherwise, the method _attach_stream() is partially executed
        and stored so it can be attached at a later point.
        """

        assert ((circuit_id is not None) and (stream_id is None)) or \
               ((circuit_id is None) and (stream_id is not None))

        # Check if we can attach right now.

        if port in self.attachers:
            attacher = self.attachers[port]

            if circuit_id:
                attacher(circuit_id=circuit_id)
            else:
                attacher(stream_id=stream_id)

            del self.attachers[port]
        else:
            # We maintain a dictionary of source ports which point to their
            # according attaching function.  At this point we only know either
            # stream or circuit ID, so we store a partially executed function.

            if circuit_id:
                self.attachers[port] = functools.partial(self._attach_stream,
                                                         circuit_id=circuit_id)
            else:
                self.attachers[port] = functools.partial(self._attach_stream,
                                                         stream_id=stream_id)

        logger.debug("Pending attachers: %d." % len(self.attachers))

    def _attach_stream(self, stream_id=None, circuit_id=None):
        """
        Attach a stream to a circuit.
        """

        logger.debug("Attaching stream %s to circuit %s." %
                     (stream_id, circuit_id))

        try:
            self.controller.attach_stream(stream_id, circuit_id)
        except stem.OperationFailed as err:
            logger.warning("Couldn't attach stream because: %s" % str(err))

        self.check_finished()

    def queue_reader(self):
        """
        Read (circuit ID, sockname) tuples from invoked probing modules.

        These tuples are then used to attach streams to their corresponding
        circuits.
        """

        logger.info("Starting thread to read from IPC queue.")

        while True:
            try:
                circ_id, sockname = self.queue.get()
            except EOFError:
                logger.info("IPC queue terminated.")
                break

            # Over the queue, a module can either signal that it finished
            # execution (by sending (None,None)) or that it is ready to have
            # its stream attached to a circuit (by sending (circuit
            # id,sockname)).

            if circ_id == sockname == None:
                self.stats.finished_streams += 1
                self.stats.print_progress()
                self.check_finished()
            else:
                _, port = sockname[0], int(sockname[1])
                logger.debug("Read from queue: %s, %s" % (circ_id,
                                                          str(sockname)))
                self.prepare_attach(port, circuit_id = circ_id)

    def check_finished(self):
        """
        Check if the scan is finished and if it is, shut down exitmap.
        """

        # Did all circuits either build or fail?

        circs_done = (self.stats.failed_circuits +
                      self.stats.successful_circuits) == self.stats.total_circuits

        # Was every built circuit attached to a stream?

        streams_done = (self.stats.finished_streams >=
                (self.stats.successful_circuits - self.stats.failed_circuits))

        logger.debug("failedCircs=%d, builtCircs=%d, totalCircs=%d, "
                     "finishedStreams=%d" % (
                         self.stats.failed_circuits,
                         self.stats.successful_circuits,
                         self.stats.total_circuits,
                         self.stats.finished_streams))

        if circs_done and streams_done:
            self.pool.close()
            self.pool.join()

            for proc in multiprocessing.active_children():
                logger.debug("Terminating remaining PID %d." % proc.pid)
                proc.terminate()

            logger.info(self.stats)
            sys.exit(0)

    def new_circuit(self, circ_event):
        """
        Invoke a new probing module when a new circuit becomes ready.
        """

        self.stats.update_circs(circ_event)
        self.check_finished()

        if circ_event.status not in [CircStatus.BUILT]:
            return

        last_hop = circ_event.path[-1]
        exit_fpr = last_hop[0]
        logger.debug("Circuit for exit relay \"%s\" is built.  "
                     "Now invoking probing module." % exit_fpr)

        self.pool.apply_async(func, args=(self.queue, circ_event.id,
                                          self.probing_module, exit_fpr))

    def new_stream(self, stream_event):
        """
        Create a function which is later used to attach a stream to a circuit.

        The attaching cannot be done right now as we do not know the stream's
        desired circuit ID at this point.  So we set up all we can at this
        point and wait for the attaching to be done in queue_reader().
        """

        if stream_event.status not in [StreamStatus.NEW,
                                       StreamStatus.NEWRESOLVE]:
            return

        port = util.get_source_port(str(stream_event))
        if not port:
            logger.warning("Couldn't extract source port from stream " \
                           "event: %s" % str(stream_event))
            return

        logger.debug("Adding attacher for new stream %s." % stream_event.id)

        self.prepare_attach(port, stream_id = stream_event.id)

    def new_event(self, event):
        """
        Dispatches new Tor controller events to the appropriate handlers.
        """

        if isinstance(event, stem.response.events.CircuitEvent):
            self.new_circuit(event)

        elif isinstance(event, stem.response.events.StreamEvent):
            self.new_stream(event)

        else:
            logger.warning("Received unexpected event %s." % str(event))
