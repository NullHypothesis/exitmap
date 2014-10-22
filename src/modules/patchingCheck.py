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
#==============
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
#EDIT ME SECTION START
#######################

# EDIT ME: exitmap needs this variable to figure out which relays can exit to the given
# destination(s).

destinations = [("live.sysinternals.com", 80)]

# EDIT ME Only one binary can be done at a time
# FORMAT: URLPATH: SHA-512_hash_of_file
tests = {#'http://nmap.org/dist/nmap-6.47-setup.exe': '23b2971973380d5c4f63607565aedfab330d6ddf7121cd50141214584444d77798dafd6da389398ff7f8a285361ac985f497b6afdd06dd60c24f38f1d1ca4f0c',
         #'http://downloads.malwarebytes.org/file/mbam/': '73bffbf9470c96fc20efefc3d90a73682c0ad135d6b2a508aa55ff13c1d3f04952e5780e4be7c45c67b64a82be70bb299716c9eb42036bad581ca153faad2bd6',
         #'http://live.sysinternals.com/psexec.exe': '12ba002c07a0ad710808db982cafece6d44510fb12d9d2473377dd5e822c42d85cce7987debfe714b2f7eb5202ad07df7cf97d2c23b849bb32d51ad89fc97b4a',
         #'https://bitcoin.org/bin/0.9.3/bitcoin-0.9.3-win32-setup.exe': '50fb1cd102c3f05c238766d2b00558e5774d527b80df48de31c5baae0e44ec285e2be81bd5715a51a9412c5534ca617d0f80c033607af674d0157909918fa60d',
         #'http://download.microsoft.com/download/5/B/C/5BC5DBB3-652D-4DCE-B14A-475AB85EEF6E/vcredist_x86.exe': 'cdd218d211a687dde519719553748f3fb36d4ac618670986a6dadb4c45b34a9c6262ba7bab243a242f91d867b041721f22330170a74d4d0b2c354aec999dbff8',
         #'http://download.microsoft.com/download/3/2/2/3224B87F-CFA0-4E70-BDA3-3DE650EFEBA5/vcredist_x64.exe': 'b6e107fa34764d336c9b59802c858845df9f8661a1beb41436fd638a044580557921e69883ed32737f853e203f0083358f642f3efe0a80fae7932c5e6137331f',
         #'http://live.sysinternals.com/tcpview.exe': '21b4c6b7e16cdc3e729fb708b5e9bded3386dbf6bdb8f286bd4ae8e9f0f59f935674730b96eca2d266e648a7badf3973e1a9ae9d365adad2fc24816de98a8e9a',
         'http://live.sysinternals.com/procexp.exe': '496245f1792ae2d6385ab27c8e450a15b7dd1ed0c2575655cea058f96ac59b4761d60f8a9037f817710d97616f5782595144201bce053b72701658f0700fda9a',
         #'http://www.ntcore.com/files/ExplorerSuite.exe': '6c255230d1d7b71a5d7dbdbdea8a1833c0f39ad2df040b3b1883ef50a9891df24ee8497fe63ea48155e8abc94c66df9de2a5cd11592a077512f1d1f5549ba172',
         #'http://www.winitor.com/tools/PeStudio839.zip': '43bf0abeb3bee646b3401753e27331989e6ca2c4d371bdd8ba70558ceb4992be9714ff0e35b83ffbe0d178cbc1dff15d92e794287399d60d9bfa3dc0011158f6',
         #'http://wjradburn.com/software/PEview.zip': '8431639fa3861ab9bf950739dddb2287b020270784f1f3885bf1a6ce5bf2e7efeab58e0b89f957edea6a3f6b992bb52ab5ad7dd75eb66f0a5e4c370da0913d8c',
         #'http://www.spybotupdates.com/files/filealyz-2.0.5.57.exe': '9e83293b5175168a52c5ee51b1da9d0d8831089d375a211a64fbf10dbc9addafef91716649aecf1ab3a17fae692c5ba0c4b3d0a3488512339ad3289777ea45d7',
         #'http://download.tuxfamily.org/notepadplus/6.6.9/npp.6.6.9.Installer.exe': '38db302e83430802e9d375ea03f0428a58fd7980fb87bf0fa420057dd2e9739099cc38643f0dbad83cf8994f3906ff10d1f4950ddafe631059de463819aae57e'
        }

#EDIT ME to the original file being downloaded
#place in exitmap root path
originalFile = 'procexp.exe'

#EDIT ME output dir in the exitmap root path
testDir = 'test'

#######################
#EDIT ME SECTION END
#######################


def sha512_for_file(filename, block_size=2**20):
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
                    #512 blocksize
                    block_size = 2 ** 9
                    tempBlock1 = binary1.read(block_size)
                    tempBlock2 = binary2.read(block_size)
                    if len(tempBlock2) < len(tempBlock1):
                        #print 'EOF', str(bin2)
                        return True
                    elif tempBlock1 != tempBlock2:
                        #something is different so we save it
                        logger.info("This is a smaller file, found a difference %s bytes in." % hex(total_count))
                        return False
                    total_count += block_size
    else:
        #file is larger so we save it
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

    for aUrl, aHash in tests.iteritems():
        try:
            data = urllib2.urlopen(aUrl, timeout=20).read()

            tmpFile = "/tmp/" + str(aUrl.replace('/', '')) + str(exit_fpr)

            with open(tmpFile, 'wb') as f:
                f.write(data)

            tempHash = sha512_for_file(tmpFile)

            if tempHash != aHash:

                #check_binary_for_matching returns False if the file is greater than original
                # or if the file is smaller and modified from original
                binCheck = check_binary_for_matching(originalFile, tmpFile)

                if binCheck is False:
                    logger.error("Detected false negative for "
                                 "<https://globe.torproject.org/#/relay/%s %s>. Saving file." % (exit_fpr, aUrl))

                    #save file strip slashes from URL
                    newFile = 'test/' + str(exit_fpr) + "_" + str(aUrl.replace('/', ''))
                    shutil.copyfile(tmpFile, newFile)
                else:
                    logger.info("File %s was truncated by %s, discarding file" % (aUrl, exit_fpr))
            else:
                logger.debug("Exit relay <https://globe.torproject.org/#/relay/%s> "
                             "passed the check test." % exit_fpr)

            os.remove(tmpFile)

        except Exception as err:
            logger.error("Error: %s %s %s" % (err, aUrl, exit_fpr))

        if not data:
            return


def main():
    """
    Entry point when invoked over the command line.
    """

    probe("n/a", None)

    return 0


if __name__ == "__main__":
    exit(main())
