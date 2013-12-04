import re
import threading
import multiprocessing

import stem

import log

logger = log.getLogger()

def getSourcePort( streamLine ):

    pattern = "SOURCE_ADDR=[0-9\.]{7,15}:([0-9]{1,5})"
    match = re.search(pattern, streamLine)
    if match:
        return int(match.group(1))

    return -1

class EventHandler( object ):

    def __init__( self, torCtrl, probingModule ):
        """
        Initialise an EventHandler object.
        """

        self.attachMap = {}
        self.torCtrl = torCtrl
        self.probingModule = probingModule

        self.manager = multiprocessing.Manager()
        self.queue = self.manager.Queue()

        threading.Thread(target=self.queueReader, args=()).start()

    def queueReader( self ):

        logger.info("Starting to read from IPC queue.")

        while True:
            circID, sockname = self.queue.get()
            _, port = sockname[0], int(sockname[1])
            logger.debug("Read from queue: %s, %s" % (circID, str(sockname)))
            self.attachMap[port] = circID

    def newCircuit( self, circEvent ):

        if circEvent.status != stem.CircStatus.BUILT:
            return

        logger.info(str(circEvent))

        exitFpr = circEvent.path[-1][0]
        logger.info("Circuit for exit relay \"%s\" is built.  " \
                    "Now invoking probing module." % exitFpr)

        proc = multiprocessing.Process(target=self.probingModule,
                                       args=(exitFpr, self.queue,
                                             circEvent.id,))
        proc.start()

    def newStream( self, streamEvent ):

        if streamEvent.status != stem.StreamStatus.NEW and \
           streamEvent.status != stem.StreamStatus.NEWRESOLVE:
            return

        logger.info("New stream event: " + str(streamEvent))
        sourcePort = getSourcePort(str(streamEvent))
        assert sourcePort != -1
        logger.debug("Source port: %d" % sourcePort)

        logger.debug("Checking attach dictionary.")

        circID = self.attachMap[sourcePort]
        del self.attachMap[sourcePort]

        logger.info("Attaching new stream %s to circuit ID %s" %
                    (str(streamEvent), circID))
        try:
            self.torCtrl.attach_stream(streamEvent.id, circID)
        except stem.OperationFailed as err:
            logger.error("Couldn't attach circuit: %s" % err)

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
