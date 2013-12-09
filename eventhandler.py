import threading
import multiprocessing

import stem
from stem import StreamStatus
from stem import CircStatus

import const
import util
import log

logger = log.getLogger()

class EventHandler( object ):

    """
    Implement a handler for asynchronous Tor events.

    The handler processes only stream and circuit events.  New streams are
    attached to their corresponding circuits since exitmap's Tor process leaves
    new streams unattached.
    """

    def __init__( self, torCtrl, probingModule, stats ):
        """
        Initialise an EventHandler object.
        """

        self.stats = stats
        self.attachMap = {}
        self.torCtrl = torCtrl
        self.probingModule = probingModule
        self.finishedStreams = 0

        self.manager = multiprocessing.Manager()
        self.queue = self.manager.Queue()

        threading.Thread(target=self.queueReader, args=()).start()

    def queueReader( self ):
        """
        Read (circuit ID, sockname) tuples from invoked probing modules.

        These tuples are later used to attach streams to their corresponding
        circuits.
        """

        logger.info("Starting to read from IPC queue.")

        while True:
            circID, sockname = self.queue.get()
            if (circID == None) and (sockname == None):
                break
            _, port = sockname[0], int(sockname[1])
            logger.debug("Read from queue: %s, %s" % (circID, str(sockname)))
            self.attachMap[port] = circID

        logger.info("Stopping to read from IPC queue.")

    def newCircuit( self, circEvent ):
        """
        Invoke a new probing module when a new circuit becomes ready.
        """

        if circEvent.status != CircStatus.BUILT:
            return

        self.stats.successfulCircuits += 1
        exitFpr = circEvent.path[-1][0]
        logger.info("Circuit for exit relay \"%s\" is built.  " \
                    "Now invoking probing module." % exitFpr)

        # Invoke the module in a dedicated process.
        proc = multiprocessing.Process(target=self.probingModule,
                                       args=(exitFpr, self.queue,
                                             circEvent.id,))
        proc.start()

    def newStream( self, streamEvent ):
        """
        Attach a new stream to its corresponding circuit.

        The missing link between the stream and its corresponding circuit is
        the TCP source port.  Probing modules inform exitmap about their source
        port by writing it to the queue.
        """

        if streamEvent.status != StreamStatus.NEW and \
           streamEvent.status != StreamStatus.NEWRESOLVE and \
           streamEvent.status != StreamStatus.CLOSED:
            return

        # We keep track of closed streams and, if necessary, terminate
        # exitmap.
        if streamEvent.status == StreamStatus.CLOSED:
            self.finishedStreams += 1
            if (self.stats.successfulCircuits == self.finishedStreams):
                self.queue.put((None, None))
                logger.info("Shutting down %s: %s" %
                            (const.TOOL_NAME, self.stats))
                exit(0)
            return

        sourcePort = util.getSourcePort(str(streamEvent))
        if not sourcePort:
            logger.error("Couldn't extract source port from stream event: %s" %
                         str(streamEvent))
            return

        try:
            circID = self.attachMap[sourcePort]
        except KeyError:
            logger.error("Couldn't find source port %d in lookup table." %
                         sourcePort)
            return
        del self.attachMap[sourcePort]

        logger.info("Attaching new stream %s to circuit ID %s." %
                    (str(streamEvent), circID))
        try:
            self.torCtrl.attach_stream(streamEvent.id, circID)
        except stem.OperationFailed as err:
            logger.error("Couldn't attach circuit: %s" % str(err))

    def newEvent( self, event ):
        """
        Dispatches new Tor controller events to the appropriate handlers.
        """

        if isinstance(event, stem.response.events.CircuitEvent):
            self.newCircuit(event)

        elif isinstance(event, stem.response.events.StreamEvent):
            self.newStream(event)

        else:
            logger.warning("Received unexpected event: " % str(event))
