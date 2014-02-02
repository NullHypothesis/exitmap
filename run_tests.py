#!/usr/bin/env python

"""
Runs our test suite. Presently this is just static checks (pyflakes and pep8),
but in the future might be extended to run unit tests.
"""

import os
import re

import stem.util.conf
import stem.util.system

CONFIG = stem.util.conf.config_dict("test", {
    "pep8.ignore": [],
    "pyflakes.ignore": [],
})

EXITMAP_BASE = os.path.dirname(__file__)


def main():
    test_config = stem.util.conf.get_config("test")
    test_config.load(os.path.join(EXITMAP_BASE, "test_settings.cfg"))

    clean_orphaned_pyc()

    # TODO: Uncomment to run unit tests in ./tests/*
    #
    # tests = unittest.defaultTestLoader.discover('test', pattern='*.py')
    # test_runner = unittest.TextTestRunner()
    # test_runner.run(tests)

    print

    static_check_issues = {}

    if is_pyflakes_available():
        for path, issues in get_pyflakes_issues([EXITMAP_BASE]).items():
            for issue in issues:
                static_check_issues.setdefault(path, []).append(issue)
    else:
        print "Pyflakes unavailable. Please install with 'sudo pip install pyflakes'."

    if is_pep8_available():
        for path, issues in get_stylistic_issues([EXITMAP_BASE]).items():
            for issue in issues:
                static_check_issues.setdefault(path, []).append(issue)
    else:
        print "Pep8 unavailable. Please install with 'sudo pip install pep8'."

    if static_check_issues:
        print "STATIC CHECKS"
        print

        for file_path in static_check_issues:
            print "* %s" % file_path

            for line_number, msg in static_check_issues[file_path]:
                line_count = "%-4s" % line_number
                print "  line %s - %s" % (line_count, msg)

            print


def clean_orphaned_pyc():
    for root, _, files in os.walk(os.path.dirname(__file__)):
        for filename in files:
            if filename.endswith('.pyc'):
                pyc_path = os.path.join(root, filename)

                if "__pycache__" in pyc_path:
                    continue

                if not os.path.exists(pyc_path[:-1]):
                    print "Deleting orphaned pyc file: %s" % pyc_path
                    os.remove(pyc_path)


def is_pyflakes_available():
    """
    Checks if pyflakes is availalbe.

    :returns: **True** if we can use pyflakes and **False** otherwise
    """

    try:
        import pyflakes
        return True
    except ImportError:
        return False


def is_pep8_available():
    """
    Checks if pep8 is availalbe.

    :returns: **True** if we can use pep8 and **False** otherwise
    """

    try:
        import pep8
        return True
    except ImportError:
        return False


def get_stylistic_issues(paths):
    """
    Checks for stylistic issues that are an issue according to the parts of PEP8
    we conform to. This alsochecks a few other stylistic issues:

    * two space indentations
    * tabs are the root of all evil and should be shot on sight
    * standard newlines (\\n), not windows (\\r\\n) nor classic mac (\\r)
    * checks that we're using 'as' for exceptions rather than a comma

    :param list paths: paths to search for stylistic issues

    :returns: **dict** of the form ``path => [(line_number, message)...]``
    """

    issues = {}

    if is_pep8_available():
        import pep8

        class StyleReport(pep8.BaseReport):
            def __init__(self, options):
                super(StyleReport, self).__init__(options)

            def error(self, line_number, offset, text, check):
                code = super(StyleReport, self).error(line_number, offset, text, check)

                if code:
                    issues.setdefault(self.filename, []).append((offset + line_number, "%s %s" % (code, text)))

        style_checker = pep8.StyleGuide(ignore=CONFIG["pep8.ignore"], reporter=StyleReport)
        style_checker.check_files(_python_files(paths))

        for path in _python_files(paths):
            with open(path) as f:
                file_contents = f.read()

                lines, prev_indent = file_contents.split("\n"), 0
                is_block_comment = False

                for index, line in enumerate(lines):
                    whitespace, content = re.match("^(\s*)(.*)$", line).groups()

                    # TODO: This does not check that block indentations are two spaces
                    # because differentiating source from string blocks ("""foo""") is more
                    # of a pita than I want to deal with right now.

                    if '"""' in content:
                        is_block_comment = not is_block_comment

                    if "\t" in whitespace:
                        issues.setdefault(path, []).append((index + 1, "indentation has a tab"))
                    elif "\r" in content:
                        issues.setdefault(path, []).append((index + 1, "contains a windows newline"))
                    elif content != content.rstrip():
                        issues.setdefault(path, []).append((index + 1, "line has trailing whitespace"))
                    elif content.lstrip().startswith("except") and content.endswith(", exc:"):
                        # Python 2.6 - 2.7 supports two forms for exceptions...
                        #
                        #   except ValueError, exc:
                        #   except ValueError as exc:
                        #
                        # The former is the old method and no longer supported in python 3
                        # going forward.

                        issues.setdefault(path, []).append((index + 1, "except clause should use 'as', not comma"))

    return issues


def get_pyflakes_issues(paths):
    """
    Performs static checks via pyflakes.

    :param list paths: paths to search for problems

    :returns: dict of the form ``path => [(line_number, message)...]``
    """

    issues = {}

    if is_pyflakes_available():
        import pyflakes.api
        import pyflakes.reporter

        class Reporter(pyflakes.reporter.Reporter):
            def __init__(self):
                self._ignored_issues = {}

                for line in CONFIG["pyflakes.ignore"]:
                    path, issue = line.split("=>")
                    self._ignored_issues.setdefault(path.strip(), []).append(issue.strip())

            def unexpectedError(self, filename, msg):
                self._register_issue(filename, None, msg)

            def syntaxError(self, filename, msg, lineno, offset, text):
                self._register_issue(filename, lineno, msg)

            def flake(self, msg):
                self._register_issue(msg.filename, msg.lineno, msg.message % msg.message_args)

            def _is_ignored(self, path, issue):
                # Paths in pyflakes_ignore are relative, so we need to check to see if our
                # path ends with any of them.

                for ignored_path, ignored_issues in self._ignored_issues.items():
                    if path.endswith(ignored_path) and issue in ignored_issues:
                        return True

                return False

            def _register_issue(self, path, line_number, issue):
                if not self._is_ignored(path, issue):
                    issues.setdefault(path, []).append((line_number, issue))

        reporter = Reporter()

        for path in _python_files(paths):
            pyflakes.api.checkPath(path, reporter)

    return issues


def _python_files(paths):
    for path in paths:
        for file_path in stem.util.system.files_with_suffix(path, '.py'):
            # This is essentially a database, not a source file. It's both huge
            # (taking a long time to process) and not pep8 compliant.

            if file_path.endswith('geoip.py'):
                continue

            yield file_path


if __name__ == '__main__':
    main()
