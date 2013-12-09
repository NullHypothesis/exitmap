import log

logger = log.getLogger()

class Statistics( object ):

    def __init__( self ):
        """
        Initialise a Statistics object.
        """

        self.totalCircuits = 0
        self.failedCircuits = 0
        self.successfulCircuits = 0
        self.modulesRun = 0

    def __str__( self ):
        """
        Print the gathered statistics.
        """

        ret = "Determining scan statistics.\n"
        ret += "Ran %d modules.\n" % self.modulesRun
        ret += "%d of %d circuits failed." % (self.failedCircuits,
                                              self.totalCircuits)
        return ret
