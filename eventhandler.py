import threading
import multiprocessing

import stem

import util
import log

logger = log.getLogger()

class EventHandler( object ):

    def __init__( self, torCtrl, probingModule, stats ):
        """
        Initialise an EventHandler object.
        """

        self.stats = stats
        self.attachMap = {}
        self.torCtrl = torCtrl
        self.probingModule = probingModule
        self.finishedStreams = 0
        self.terminate = False

        self.manager = multiprocessing.Manager()
        self.queue = self.manager.Queue()

        threading.Thread(target=self.queueReader, args=()).start()

    def queueReader( self ):

        logger.info("Starting to read from IPC queue.")

        while not self.terminate:
            circID, sockname = self.queue.get()
            if (circID == None) and (sockname == None):
                continue
            _, port = sockname[0], int(sockname[1])
            logger.debug("Read from queue: %s, %s" % (circID, str(sockname)))
            self.attachMap[port] = circID

        logger.info("Stopping to read from IPC queue.")

    def newCircuit( self, circEvent ):

        if circEvent.status != stem.CircStatus.BUILT:
            return

        self.stats.successfulCircuits += 1
        exitFpr = circEvent.path[-1][0]
        logger.info("Circuit for exit relay \"%s\" is built.  " \
                    "Now invoking probing module." % exitFpr)

        proc = multiprocessing.Process(target=self.probingModule,
                                       args=(exitFpr, self.queue,
                                             circEvent.id,))
        proc.start()

    def newStream( self, streamEvent ):

        logger.debug("stream event: %s" % str(streamEvent))

        if streamEvent.status != stem.StreamStatus.NEW and \
           streamEvent.status != stem.StreamStatus.NEWRESOLVE and \
           streamEvent.status != stem.StreamStatus.CLOSED:
            return

        if streamEvent.status == stem.StreamStatus.CLOSED:
            self.finishedStreams += 1
            if (self.stats.successfulCircuits == self.finishedStreams):
                logger.info("Time to die!")
                self.terminate = True
                self.queue.put((None, None))
                print self.stats
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
