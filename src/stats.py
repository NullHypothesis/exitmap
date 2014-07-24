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

from datetime import datetime

import log

logger = log.get_logger()


class Statistics(object):
    def __init__(self):
        """
        Initialise a Statistics object.
        """

        self.start_time = datetime.now()
        self.total_circuits = 0
        self.failed_circuits = 0
        self.successful_circuits = 0
        self.modules_run = 0

    def print_progress(self, sampling=10):
        """
        Print statistics about ongoing probing process.
        """

        if self.successful_circuits % sampling:
            return

        assert self.total_circuits > 0

        percent_done = (float(100) / self.total_circuits) * \
                       self.successful_circuits

        logger.info("Probed %d out of %d exit relays, so we are %.2f%% done." %
                    (self.successful_circuits,
                     self.total_circuits,
                     percent_done))

    def __str__(self):
        """
        Print the gathered statistics.
        """

        ret = "Determining scan statistics.\n"
        ret += "Ran %d modules.\n" % self.modules_run
        ret += "%d of %d circuits failed.\n" % (self.failed_circuits,
                                                self.total_circuits)
        ret += "Scan time: %s." % str(datetime.now() - self.start_time)

        return ret
