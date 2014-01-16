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

TOOL_NAME = "exitmap"

# Entry guard/middle relay used as only hop before the respective exit relay.
# FIXME: Add your relay's fingerprint here.
FIRST_HOP = ""


# Seconds after which circuits are no longer considered to be used for streams.
CIRCUIT_TIMEOUT = 10

# How many seconds in between circuit creations do we wait?  Do *not* lower
# this value unless you know what you are doing!
CIRCUIT_BUILD_DELAY = 2

# Value which signals the queue reader to terminate.
TERMINATE = None

# The data directory of exitmap's Tor process.
TOR_DATA_DIRECTORY = "/tmp/exitmap_tor_datadir/"

# The SOCKS port of exitmap's Tor process.
TOR_SOCKS_PORT = 45678

# The control port of exitmap's Tor process.
TOR_CONTROL_PORT = 45679
