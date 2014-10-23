#!/usr/bin/env python

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
# ==============
# Copyright 2014 Josh Pitts josh.pitts@leviathansecurity.com
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
patchingCheck.py
by Joshua Pitts josh.pitts@leviathansecurity.com
twitter: @midnite_runr

Module to detect binary patching.

-USAGE-
Make appropriate changes in the EDIT ME SECTION

Then run:
./bin/exitmap -d 5 patchingCheck

"""

import urllib2
import os
import log
import hashlib
import shutil

logger = log.get_logger()

#######################
# EDIT ME SECTION START
#######################

# EDIT ME: exitmap needs this variable to figure out which
# relays can exit to the given destination(s).

destinations = [("live.sysinternals.com", 80)]

# EDIT ME
# Must provide a Download link and test binary with FULL PATH
tests = {'http://live.sysinternals.com/procexp.exe':
         '/tmp/procexp.exe',
         'http://www.ntcore.com/files/ExplorerSuite.exe':
         '/tmp/ExplorerSuite.exe',
         }

# EDIT ME
# output directory use FULL PATH
testDir = '/tmp/test/'

#######################
# EDIT ME SECTION END
#######################


def sha512_for_file(filename, block_size=2 ** 20):
    sha = hashlib.sha512()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(128 * sha.block_size), b''):
            sha.update(chunk)
    return sha.hexdigest()


def check_binary_for_matching(bin1, bin2):
    '''
    bin1 is the original file
    return False if the files are different
    return True if the same file until EOF
    '''

    if os.path.getsize(bin2) < os.path.getsize(bin1):
        with open(bin2, 'r+b') as binary2:
            with open(bin1, 'r+b') as binary1:
                total_count = 0
                while True:
                    # 512 blocksize
                    block_size = 2 ** 9
                    tempBlock1 = binary1.read(block_size)
                    tempBlock2 = binary2.read(block_size)
                    if len(tempBlock2) < len(tempBlock1):
                        return True
                    elif tempBlock1 != tempBlock2:
                        # something is different so we save it
                        logger.info("This is a smaller file, found "
                                    "a difference %s bytes in."
                                    % hex(total_count))
                        return False
                    total_count += block_size
    else:
        # file is larger so we save it
        return False


def probe(exit_fpr, cmd):
    """
    Probe the given exit relay and look for modified binaries.
    """

    if not os.path.exists(testDir):
        os.makedirs(testDir)

    logger.debug("Now probing exit relay "
                 "<https://globe.torproject.org/#/relay/%s>." % exit_fpr)

    data = None

    for aUrl, originalFile in tests.iteritems():
        aHash = sha512_for_file(originalFile)
        try:
            data = urllib2.urlopen(aUrl, timeout=20).read()

        except Exception as err:
            logger.error("Error: %s %s %s" % (err, aUrl, exit_fpr))

        if not data:
            return

        tmpFile = "/tmp/" + str(aUrl.replace('/', '')) + str(exit_fpr)

        with open(tmpFile, 'wb') as f:
            f.write(data)

        tempHash = sha512_for_file(tmpFile)

        if tempHash != aHash:

            # check_binary_for_matching returns False if the file is greater
            # than original or if the file is smaller and modified
            binCheck = check_binary_for_matching(originalFile, tmpFile)

            if binCheck is False:
                logger.error("Detected false negative for "
                             "<https://globe.torproject.org/#/relay/%s %s>. "
                             "Saving file." % (exit_fpr, aUrl))

                # save file strip slashes from URL
                newFile = testDir.rstrip('/') + '/' + str(exit_fpr) + "_" \
                                              + str(aUrl.replace('/', ''))

                shutil.copyfile(tmpFile, newFile)
            else:
                logger.info("File %s was truncated by %s, discarding file" %
                            (aUrl, exit_fpr))
        else:
            logger.debug("Exit relay "
                         "<https://globe.torproject.org/#/relay/%s> "
                         "passed the check test." % exit_fpr)

        os.remove(tmpFile)


def main():
    """
    Entry point when invoked over the command line.
    """

    probe("n/a", None)

    return 0


if __name__ == "__main__":
    exit(main())
