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

import stem
from stem import StreamStatus
from stem import CircStatus

import command
import const
import mysocks
import util
import log

logger = log.getLogger()


class EventHandler(object):
    """
    Implement a handler for asynchronous Tor events.

    The handler processes only stream and circuit events.  New streams are
    attached to their corresponding circuits since exitmap's Tor process leaves
    new streams unattached.
    """

    def __init__(self, torCtrl, probingModule, stats):
        """
        Initialise an EventHandler object.
        """

        self.stats = stats
        self.attachers = {}
        self.torCtrl = torCtrl
        self.probingModule = probingModule
        self.finishedStreams = 0
        self.origsock = socket.socket

        self.ourStreamEvents = [
            StreamStatus.NEW,
            StreamStatus.NEWRESOLVE,
            StreamStatus.CLOSED,
            StreamStatus.FAILED,
            StreamStatus.DETACHED,
        ]

        self.ourCircuitEvents = [
            CircStatus.BUILT,
            CircStatus.FAILED,
            CircStatus.CLOSED,
        ]

        self.manager = multiprocessing.Manager()
        self.queue = self.manager.Queue()

        threading.Thread(target=self.queueReader, args=()).start()

        mysocks.setdefaultproxy(mysocks.PROXY_TYPE_SOCKS5, "127.0.0.1",
                                const.TOR_SOCKS_PORT)

    def prepareAttach(self, port, circuitID=None, streamID=None):
        """
        Prepare for attaching a stream to a circuit.

        If we already have the corresponding stream/circuit, it can be attached
        right now.  Otherwise, the method _attachStream() is partially executed
        and stored so it can be attached at a later point.
        """

        assert ((circuitID is not None) and (streamID is None)) or \
               ((circuitID is None) and (streamID is not None))

        # Check if we can attach right now.

        if port in self.attachers:
            attacher = self.attachers[port]

            if circuitID:
                attacher(circuitID=circuitID)
            else:
                attacher(streamID=streamID)

            del self.attachers[port]
        else:
            # We maintain a dictionary of source ports which point to their
            # according attaching function.  At this point we only know either
            # stream or circuit ID, so we store a partially executed function.

            if circuitID:
                self.attachers[port] = functools.partial(self._attachStream,
                                                         circuitID=circuitID)
            else:
                self.attachers[port] = functools.partial(self._attachStream,
                                                         streamID=streamID)

        logger.debug("Pending attachers: %d." % len(self.attachers))

    def _attachStream(self, streamID=None, circuitID=None):
        """
        Attach a stream to a circuit.
        """

        logger.debug("Attaching stream %s to circuit %s." %
                     (streamID, circuitID))

        try:
            self.torCtrl.attach_stream(streamID, circuitID)
        except stem.OperationFailed as err:
            logger.error("Couldn't attach stream: %s" % str(err))

    def queueReader(self):
        """
        Read (circuit ID, sockname) tuples from invoked probing modules.

        These tuples are then used to attach streams to their corresponding
        circuits.
        """

        logger.info("Starting to read from IPC queue.")

        while True:
            circID, sockname = self.queue.get()

            if circID == sockname == const.TERMINATE:
                break

            _, port = sockname[0], int(sockname[1])
            logger.debug("Read from queue: %s, %s" % (circID, str(sockname)))

            self.prepareAttach(port, circuitID=circID)

        logger.info("Stopping to read from IPC queue.")

    def isFinished(self):
        """
        Check if the scan is finished and if it is, shut down exitmap.
        """

        # Did all circuits either build or fail?

        circsDone = (self.stats.failedCircuits +
                     self.stats.successfulCircuits) == self.stats.totalCircuits

        # Was every built circuit attached to a stream?

        streamsDone = (self.finishedStreams >= self.stats.successfulCircuits)

        logger.debug("failedCircs=%d, builtCircs=%d, totalCircs=%d, "
                     "finishedStreams=%d" % (
                         self.stats.failedCircuits,
                         self.stats.successfulCircuits,
                         self.stats.totalCircuits,
                         self.finishedStreams))

        if circsDone and streamsDone:
            # Terminate the thread which handles the queue.
            socket.socket = mysocks._orgsocket
            self.queue.put((None, None))
            logger.info("Finished scan: %s" % self.stats)
            exit(0)

    def newCircuit(self, circEvent):
        """
        Invoke a new probing module when a new circuit becomes ready.
        """

        if circEvent.status not in self.ourCircuitEvents:
            return

        # Keep track of how many circuits are already finished.

        if circEvent.status in [CircStatus.FAILED, CircStatus.CLOSED]:
            logger.info("Circuit closed because: %s" % str(circEvent.reason))
            self.stats.failedCircuits += 1
            return

        self.stats.successfulCircuits += 1
        exitFpr = circEvent.path[-1][0]
        logger.info("Circuit for exit relay \"%s\" is built.  "
                    "Now invoking probing module." % exitFpr)

        cmd = command.Command("/tmp/torsocks.conf", self.queue, circEvent.id,
                               self.origsock)
        socket.socket = mysocks.socksocket
        mysocks.setqueue(self.queue, circEvent.id)

        # Invoke the module in a dedicated process.
        proc = multiprocessing.Process(target=self.probingModule,
                                       args=(exitFpr, cmd,))
        proc.start()

    def newStream(self, streamEvent):
        """
        Create a function which is later used to attach a stream to a circuit.

        The attaching cannot be done right now as we do not know the stream's
        desired circuit ID at this point.  So we set up all we can at this
        point and wait for the attaching to be done in queueReader().
        """

        if streamEvent.status not in self.ourStreamEvents:
            return

        # Keep track of how many streams are already finished.

        if streamEvent.status in [StreamStatus.CLOSED, StreamStatus.FAILED,
                                  StreamStatus.DETACHED]:
            self.finishedStreams += 1
            return

        port = util.getSourcePort(str(streamEvent))
        if not port:
            logger.error("Couldn't extract source port from stream event: %s" %
                         str(streamEvent))
            return

        logger.debug("Adding attacher for new stream %s." % streamEvent.id)

        self.prepareAttach(port, streamID=streamEvent.id)

    def newEvent(self, event):
        """
        Dispatches new Tor controller events to the appropriate handlers.
        """

        if isinstance(event, stem.response.events.CircuitEvent):
            self.newCircuit(event)

        elif isinstance(event, stem.response.events.StreamEvent):
            self.newStream(event)

        else:
            logger.warning("Received unexpected event: " % str(event))

        self.isFinished()
