#!/usr/bin/env python
from setuptools import setup

setup(
    name="exitmap",
    author="Philipp Winter",
    author_email="phw@nymity.ch",
    packages=["exitmap"],
    package_dir={"exitmap": "src"},
    entry_points={"console_scripts": ["exitmap = exitmap:main"]},
    license="GPLv3+",
    platforms="any",
)
