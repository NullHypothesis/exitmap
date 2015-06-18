# Copyright 2013-2015 Philipp Winter <phw@nymity.ch>
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
Exports custom exceptions.
"""


class ExitSelectionError(Exception):

    """
    Represents an error during selection of exit relays.
    """

    pass


class PathSelectionError(Exception):

    """
    Represents an error during selection of a path for a circuit.
    """

    pass


class SOCKSv5Error(Exception):

    """
    Represents an error while negotiating SOCKSv5.
    """

    pass
