import re

def getSourcePort( streamLine ):

    pattern = "SOURCE_ADDR=[0-9\.]{7,15}:([0-9]{1,5})"
    match = re.search(pattern, streamLine)
    if match:
        return int(match.group(1))

    return None
