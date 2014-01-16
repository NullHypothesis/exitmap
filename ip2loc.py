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

import sys, re
import geoip

def binarySearch( begin, ip, end ):
	middle = begin + ((end - begin) / 2)
	if ip < int(geoip.db[middle][0]):
		if (middle-1) == end:
			return ""
		return binarySearch(begin, ip, middle-1)
	elif ip > int(geoip.db[middle][1]):
		if (middle+1) == begin:
			return ""
		return binarySearch(middle+1, ip, end)
	else:
		return "%s" % geoip.db[middle][2]

def resolve( ip ):
	d1, d2, d3, d4 = ip.split('.')
	return  binarySearch(0, int(d1) << 24 | int(d2) << 16 | \
		int(d3) << 8 | int(d4), len(geoip.db)-1)
