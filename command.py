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

import socket
import threading
import subprocess

import log
import util

logger = log.get_logger()


class Command(object):
    def __init__(self, torsocks_conf, queue, circ_id, origsock):
        self.env = dict()
        self.env["TORSOCKS_CONF_FILE"] = torsocks_conf
        self.env["TORSOCKS_LOG_LEVEL"] = "5"

        self.command = ["/usr/local/bin/torsocks"]
        self.process = None
        self.stdout = None
        self.stderr = None
        self.queue = queue
        self._origsocket = origsock
        self.circ_id = circ_id
        self.pattern = "Connection on fd [0-9]+ originating " \
                       "from [^:]+:([0-9]{1,5})"

    def _invoke_process(self):
        """
        Invoke the process and wait for it to finish.

        If a callback was specified, it is called with the process' output as
        argument and together with a function which can be used to terminate
        the process.
        """

        # Start process and redirect stderr to stdout.  That makes it much more
        # convenient for us to parse the output.
        self.process = subprocess.Popen(self.command, env=self.env,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT)

        if self.output_callback:
            # Read the process' output line by line and pass it to the
            # callback.

            while True:
                line = self.process.stdout.readline().strip()

                if line:
                    # Look for torsocks' source port before we pass the line on
                    # to the module.

                    port = util.extract_pattern(line, self.pattern)

                    if port is not None:
                        # socket.socket is probably monkey-patched.  We need,
                        # however, the original implementation.

                        tmpsock = socket.socket
                        socket.socket = self._origsocket
                        self.queue.put([self.circ_id, ("127.0.0.1", int(port))])
                        socket.socket = tmpsock

                    self.output_callback(line, self.process.terminate)
                else:
                    break

        # Wait for the process to finish.

        self.stdout, self.stderr = self.process.communicate()

    def execute(self, command, timeout=10, output_callback=None):
        self.command += command
        self.output_callback = output_callback

        logger.debug("Invoking \"%s\" in environment \"%s\"" %
                     (' '.join(self.command), str(self.env)))

        thread = threading.Thread(target=self._invoke_process)
        thread.start()
        thread.join(timeout)

        # Kill the process if it doesn't react.  With fire^Wterminate().

        if thread.isAlive():
            logger.error("Terminating subprocess after waiting for more "
                         "than %d seconds." % timeout)

            try:
                self.process.terminate()
            except OSError as e:
                logger.error(e)

            thread.join()

        return (self.stdout, self.stderr)


# Alias class name to provide more intuitive interface.
new = Command
