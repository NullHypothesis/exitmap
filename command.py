import socket
import threading
import subprocess

import log
import util

logger = log.getLogger()

class Command( object ):

    def __init__( self, torsocksConf, queue, circID, origsock ):

        self.env = dict()
        self.env["TORSOCKS_CONF_FILE"] = torsocksConf
        self.env["TORSOCKS_LOG_LEVEL"] = "5"

        self.command = ["/usr/local/bin/torsocks"]
        self.process = None
        self.stdout = None
        self.stderr = None
        self.queue = queue
        self._origsocket = origsock
        self.circID = circID
        self.pattern = "Connection on fd [0-9]+ originating " \
                       "from [^:]+:([0-9]{1,5})"

    def _invokeProcess( self ):
        """
        Invoke the process and wait for it to finish.

        If a callback was specified, it is called with the process' output as
        argument and together with a function which can be used to terminate
        the process.
        """

        self.process = subprocess.Popen(self.command, env=self.env,
                                        stdout = subprocess.PIPE,
                                        stderr = stdout)

        if self.outputCallback:

            # Read the process' output line by line and pass it to the
            # callback.
            while True:

                if self.outputWatch == "stdout":
                    line = self.process.stdout.readline().strip()
                else:
                    line = self.process.stderr.readline().strip()

                if line:
                    # Look for torsocks' source port before we pass the line on
                    # to the module.
                    port = util.extractPattern(line, self.pattern)
                    if port is not None:
                        # socket.socket is probably monkey-patched.  We need,
                        # however, the original implementation.
                        tmpsock = socket.socket
                        socket.socket = self._origsocket
                        self.queue.put([self.circID, ("127.0.0.1", int(port))])
                        socket.socket = tmpsock

                    self.outputCallback(line, self.process.terminate)
                else:
                    break

        # Wait for the process to finish.
        self.stdout, self.stderr = self.process.communicate()


    def execute( self, command, timeout=10, outputCallback=None,
                 outputWatch="None" ):

        self.command += command
        self.outputCallback = outputCallback
        self.outputWatch = outputWatch

        logger.debug("Invoking \"%s\" in environment \"%s\"" %
                     (' '.join(self.command), str(self.env)))

        thread = threading.Thread(target=self._invokeProcess)
        thread.start()
        thread.join(timeout)

        # Kill the process if it doesn't react.  With fire^Wterminate().
        if thread.isAlive():
            logger.debug("Terminating subprocess after waiting for more " \
                         "than %d seconds." % timeout)
            try:
                self.process.terminate()
            except OSError as e:
                logger.error(e)

            thread.join()

        return (self.stdout, self.stderr)

# Alias class name to provide more intuitive interface.
new = Command
