import time

class Circuit( object ):

    def __init__( self, circuitID ):
        self.circuitID = circuitID
        self.created = time.time()

    def getID( self ):
        return self.circuitID

    def getAge( self ):
        return time.time() - self.created

    def __str__( self ):
        return str(self.circuitID)

new = Circuit
