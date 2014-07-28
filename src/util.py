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

import re
import os

from stem.descriptor.reader import DescriptorReader

def get_consensus_path(args):

    # If no consensus was given over the command line, we take the one in the
    # data directory.

    if args.consensus:
        return args.consensus
    else:
        return os.path.join(args.temp_dir, "cached-consensus")

def relay_in_consensus(fingerprint, consensus):
    """
    Check if a relay is part of the consensus.

    If the relay identified by `fingerprint' is part of the given `consensus',
    True is returned.  If not, False is returned.
    """

    fingerprint = fingerprint.upper()

    with DescriptorReader(consensus) as reader:
        for descriptor in reader:
            if descriptor.fingerprint == fingerprint:
                return True

    return False

def get_source_port(stream_line):
    pattern = "SOURCE_ADDR=[0-9\.]{7,15}:([0-9]{1,5})"
    match = re.search(pattern, stream_line)

    if match:
        return int(match.group(1))

    return None


def extract_pattern(line, pattern):
    """
    Look for the given 'pattern' in 'line'.

    If it is found, the match is returned.  Otherwise, 'None' is returned.
    """

    match = re.search(pattern, line)

    if match:
        return match.group(1)

    return None
