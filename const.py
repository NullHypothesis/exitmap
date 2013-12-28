TOOL_NAME = "exitmap"

# Entry guard/middle relay used as only hop before the respective exit relay.
# FIXME: Add your relay's fingerprint here.
FIRST_HOP = ""


# Seconds after which circuits are no longer considered to be used for streams.
CIRCUIT_TIMEOUT = 10

# How many seconds in between circuit creations do we wait?
CIRCUIT_BUILD_DELAY = 0.01

# Value which signals the queue reader to terminate.
TERMINATE = None

# The data directory of exitmap's Tor process.
TOR_DATA_DIRECTORY = "/tmp/exitmap_tor_datadir/"

# The SOCKS port of exitmap's Tor process.
TOR_SOCKS_PORT = 45678

# The control port of exitmap's Tor process.
TOR_CONTROL_PORT = 45679
