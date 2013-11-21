import logging

import const

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(fmt="%(asctime)s [%(levelname)s]: "
                                           "%(message)s"))

logger = logging.getLogger(const.TOOL_NAME)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

def getLogger(  ):
    """
    Returns a logger.
    """

    return logger
