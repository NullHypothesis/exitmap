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
