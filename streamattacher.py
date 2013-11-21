"""
Provides the 'StreamAttacher' class.
"""

import stem

import log

logger = log.getLogger()

class StreamAttacher( object ):

    """
    Attaches new streams to circuits.

    New streams (i.e., SOCKS connections stemming from a local application) are
    attached to a circuit which ends with an exit relay to probe.  Attaching is
    done in a semi-smart way by keeping state and making sure that an exit
    relay sees the DNS request as well as the corresponding TCP stream.
    Everything else might attract suspicion.
    """

    def __init__( self, circuitPool, ctrl ):
        """
        Initialises a new 'StreamAttacher' object.
        """

        self.circuitPool = circuitPool
        self.ctrl = ctrl
        self.count = 1

        # List of circuits which were already used for DNS but not yet for a
        # SOCKS connection.
        self.circuits = []

    # close circuits after timeout
    def newEvent( self, stream, timeout=20 ):
        """
        Attaches the given 'stream' to a ready-to-use circuit.
        """

        if stream.status not in ["NEW", "NEWRESOLVE"]:
            return

        logger.debug("New async event: %s" % str(stream))

        # Attach stream to a new circuit.
        if stream.status == "NEWRESOLVE":

            circuit = self.circuitPool.getCircuit()
            if circuit == None:
                logger.warning("No more circuits.  Terminating.")
                exit(1)

            self.circuits.append(circuit)

        # Attach stream to a circuit which was already used for a 'NEWRESOLVE'
        # event.
        elif stream.status == "NEW":

            logger.info("This is stream #%d." % self.count)
            self.count += 1

            #assert len(self.circuits) > 0
            if len(self.circuits) == 0:
                circuit = self.circuitPool.getCircuit()
                if circuit == None:
                    logger.warning("No more circuits.  Terminating.")
                    exit(1)
            else:
                logger.debug("Reusing circuit which was already used for DNS.")
                circuit = self.circuits.pop()

        logger.debug("Attaching stream #%s to circuit #%s." %
                     (stream.id, circuit))

        try:
            self.ctrl.attach_stream(stream.id, circuit)
        except (stem.InvalidRequest,
                stem.UnsatisfiableRequest,
                stem.OperationFailed) as err:
            logger.error("Couldn't attach circuit: %s" % err)

# Alias class name to provide more intuitive interface.
new = StreamAttacher
