#!/usr/bin/env python2

# Copyright 2016 Philipp Winter <phw@nymity.ch>
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
""" Unit tests for the relay selector module."""

import unittest
import sys
sys.path.insert(0, 'src/')
import relayselector


class TestRelaySelector(unittest.TestCase):
    """Test the torsocks module."""

    def test_get_exits(self):
        with self.assertRaises(SystemExit) as exits:
            relayselector.get_exits('/tmp',
                                    good_exit=True,
                                    bad_exit=True,
                                    version=None,
                                    nickname=None,
                                    address=None,
                                    country_code='at',
                                    requested_exits=None,
                                    destinations=None)
        self.assertEqual(exits.exception.code, 1)


if __name__ == '__main__':
    unittest.main()
