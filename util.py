import re


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
