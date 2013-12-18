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
