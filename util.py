import re

from stem.descriptor.reader import DescriptorReader

def get_consensus_path(args):

    # If no consensus was given over the command line, we take the one in the
    # data directory.

    if args.consensus:
        return args.consensus
    else:
        return args.temp_dir + "/cached-consensus"

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
