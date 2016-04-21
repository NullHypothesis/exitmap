# Copyright 2013-2016 Philipp Winter <phw@nymity.ch>
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

"""
Provides functions to keep track of scanning statistics.
"""

import logging
from datetime import datetime

from stem import CircStatus

log = logging.getLogger(__name__)


class Statistics(object):

    """
    Keep track of scanning statistics.
    """

    def __init__(self):
        """
        Initialise a Statistics object.
        """

        self.start_time = datetime.now()
        self.total_circuits = 0
        self.failed_circuits = 0
        self.successful_circuits = 0
        self.modules_run = 0
        self.finished_streams = 0
        self.failed_streams = 0

    def update_circs(self, circ_event):
        """
        Update statistics with the given circuit event."
        """

        if circ_event.status in [CircStatus.FAILED]:

            log.debug("Circuit failed because: %s" % str(circ_event.reason))
            self.failed_circuits += 1

        elif circ_event.status in [CircStatus.BUILT]:

            self.successful_circuits += 1

    def print_progress(self, sampling=50):
        """
        Print statistics about ongoing probing process.
        """

        if (sampling == 0) or (self.finished_streams % sampling):
            return

        if self.total_circuits == 0:
            return

        percent_done = (self.successful_circuits /
                        float(self.total_circuits)) * 100

        log.info("Probed %d out of %d exit relays, so we are %.2f%% done." %
                 (self.successful_circuits, self.total_circuits, percent_done))

    def __str__(self):
        """
        Print the gathered statistics.
        """

        percent = 0
        if self.total_circuits > 0:
            percent = (self.failed_circuits / float(self.total_circuits)) * 100

        return ("Ran %d module(s) in %s and %d/%d circuits failed (%.2f%%)." %
                (self.modules_run,
                 str(datetime.now() - self.start_time),
                 self.failed_circuits,
                 self.total_circuits,
                 percent))
