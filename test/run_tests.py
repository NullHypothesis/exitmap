#!/usr/bin/env python2

"""
Runs our test suite. Presently this is just static checks (pyflakes and pep8),
but in the future might be extended to run unit tests.
"""

import os

import stem.util.conf
import stem.util.test_tools

EXITMAP_BASE = os.path.dirname(__file__)


def main():
    test_config = stem.util.conf.get_config("test")
    test_config.load(os.path.join(EXITMAP_BASE, "test_settings.cfg"))

    orphaned_pyc = stem.util.test_tools.clean_orphaned_pyc(EXITMAP_BASE)

    for path in orphaned_pyc:
        print "Deleted orphaned pyc file: %s" % path

    # TODO: Uncomment to run unit tests in ./tests/*
    #
    # tests = unittest.defaultTestLoader.discover('test', pattern='*.py')
    # test_runner = unittest.TextTestRunner()
    # test_runner.run(tests)

    print

    static_check_issues = {}

    if stem.util.test_tools.is_pyflakes_available():
        for path, issues in stem.util.test_tools.get_pyflakes_issues([EXITMAP_BASE]).items():
            for issue in issues:
                static_check_issues.setdefault(path, []).append(issue)
    else:
        print "Pyflakes unavailable. Please install with 'sudo pip install pyflakes'."

    if stem.util.test_tools.is_pep8_available():
        for path, issues in stem.util.test_tools.get_stylistic_issues([EXITMAP_BASE]).items():
            for issue in issues:
                static_check_issues.setdefault(path, []).append(issue)
    else:
        print "Pep8 unavailable. Please install with 'sudo pip install pep8'."

    if static_check_issues:
        print "STATIC CHECKS"
        print

        for file_path in static_check_issues:
            print "* %s" % file_path

            for line_number, msg, code in static_check_issues[file_path]:
                line_count = "%-4s" % line_number
                print "  line %s - %s" % (line_count, msg)

            print


if __name__ == '__main__':
    main()
