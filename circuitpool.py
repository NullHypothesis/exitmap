"""
Provides the 'CircuitPool' class.
"""

import time
import random

import stem

import log
import const
import circuit

logger = log.getLogger()

class CircuitPool( object ):

    """
    Turns a list of exit relay fingerprints into ready-to-use circuits.

    At any given time, the pool manages some preemptively created circuits to
    prevent creation delays when an applciation is requesting circuits.
    """

    def __init__( self, ctrl, exitRelays ):
        """
        Initialises a new 'CircuitPool' object.
        """

        random.shuffle(exitRelays)

        self.ctrl = ctrl
        self.exitRelays = exitRelays
        self.pool = []

        logger.info("Initialising circuit pool with %d exit relays." %
                     len(exitRelays))

        logger.debug("Preemptively creating circuits.")
        self._fillPool()
        time.sleep(1)

    def _addCircuit( self, awaitBuild=False ):
        """
        Grabs a new exit relay fingerprint and creates a circuit with it.

        If circuit creation fails, the next exit is used.
        """

        circuitID = None

        while (circuitID is None):

            if len(self.exitRelays) == 0:
                logger.warning("No more exit relay fingerprints to create " \
                               "circuits with.")
                return

            exitRelay = self.exitRelays.pop(0)

            logger.debug("Attempting to create circuit with '%s' as exit " \
                         "relay." % exitRelay)

            # TODO: By default, randomly chosen middle relays should be used.

            try:
                circuitID = self.ctrl.new_circuit([const.FIRST_HOP, exitRelay],
                                                  await_build=awaitBuild)
            except (stem.InvalidRequest, stem.CircuitExtensionFailed,
                    stem.ControllerError) as error:

                logger.warning("Could not establish circuit with '%s'.  " \
                               "Skipping to next exit (error=%s)." %
                               (exitRelay, error))

        logger.debug("Created circuit #%s with '%s' as exit relay." %
                     (circuitID, exitRelay))

        self.pool.append(circuit.new(circuitID))

    def _fillPool( self, awaitBuild=False ):

        if len(self.pool) == const.CIRCUIT_POOL_SIZE:
            return

        logger.debug("Attempting to refill the circuit pool to size %d." %
                     const.CIRCUIT_POOL_SIZE)

        while (len(self.exitRelays) > 0) and \
              (len(self.pool) != const.CIRCUIT_POOL_SIZE):

            self._addCircuit(awaitBuild)

    def _findCircuitInPool( self ):

        circuit = None

        # go over circuit pool once
        poolLen = len(self.pool)
        for idx in xrange(poolLen):

            if idx >= len(self.pool):
                return None

            logger.debug("idx=%d, poolsize=%d" % (idx, len(self.pool)))

            circuit = self.pool[idx] # that's a Circuit() object
            if circuit.getAge() > const.CIRCUIT_TIMEOUT:
                logger.debug("Circuit #%s exceeded maximum age.  Time to die."
                             % circuit)
                self.pool.pop(idx)
                if len(self.pool) == 0:
                    return None

                self.closeCircuit(circuit.getID())

            try:
                c = self.ctrl.get_circuit(circuit.getID())
            except (stem.ControllerError, ValueError) as error:
                logger.error("Could not get circuit #%s.  Skipping and " \
                             "trying the next one (error=%s)." %
                             (circuit, error))
                self.pool.pop(idx)
                if len(self.pool) == 0:
                    return None
                self.closeCircuit(circuit.getID())
                continue

            if c.status == "BUILT":
                logger.debug("Circuit #%s has status 'BUILT' and is OK to " \
                             "return." % circuit)
                break

            elif c.status in ["EXTENDED", "LAUNCHED"]:
                logger.debug("Circuit #%s not yet ready.  Skipping." %
                             circuit)
                continue

            else:
                logger.warning("Circuit #%d is in status '%s'.  Closing it " \
                               "and taking the next one." %
                               (circuit, c.status))
                self.closeCircuit(circuit.getID())
                self.pool.pop(idx)
                if len(self.pool) == 0:
                    return None
                continue

        if len(self.pool):
            self.pool.pop(idx)

        self._fillPool()

        return circuit

    def getCircuit( self ):
        """
        Returns a ready-to-use circuit.

        If the pool is empty, 'None' is returned instead.
        """

        circuit = None
        backoff = 2

        while len(self.pool):

            circuit = self._findCircuitInPool()
            if circuit:
                return circuit.getID()

            logger.debug("Wrapping over %d-length pool." % len(self.pool))

            # exponential backoff to give circuits time to be created.
            duration = backoff / float(10)
            logger.debug("Backing off %.3f seconds." % duration)
            time.sleep(duration)
            backoff *= 2

            # TODO - if backoff gets too high, try to add more relays. the
            # current pool might simply suck.
            # also, bad circuits should be removed soon because this
            # algorithm tends to accumulate sucky circuits. they won't go.

        if circuit:
            return circuit.getID()
        else:
            return circuit

    def closeCircuit( self, circuitID ):
        """
        Close the given circuit.
        """

        try:
            self.ctrl.close_circuit(circuitID)
        except (stem.InvalidArguments, stem.InvalidRequest) as error:
            logger.error("Circuit could not be closed (error=%s)." % error)
            return

        idx = 0
        for circuit in self.pool:
            idx += 1
            if circuit.getID() == circuitID:
                self.pool.pop(idx)
                return

# Alias class name to provide more intuitive interface.
new = CircuitPool
