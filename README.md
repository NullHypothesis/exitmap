Overview
--------

`exitmap` is a fast and modular Python-based scanner for Tor exit relays.
Modules implement tasks which can be executed over all exit relays or a subset
of them.

The tool uses [`Stem`](https://stem.torproject.org) to initiate circuits over
all given exit relays and as soon as `tor` notifies `exitmap` of an established
circuit, a module is invoked over the newly established circuit.

Among other things, `exitmap` has been used to check for false positives on
the Tor Project's [check](https://check.torproject.org) service.

Installation
------------

`exitmap` uses the library `Stem` to communicate with Tor.  On Debian jessie
and newer, you can install `Stem` by executing:

    # apt-get install python-stem

Running exitmap
---------------

You can run `exitmap` with the checktest module by executing:

    $ python exitmap.py checktest

To run the same test over German exit relays only, execute:

    $ python exitmap.py -C DE checktest

Alternatives
------------

Don't like `exitmap`?  Then have a look at
[`tortunnel`](http://www.thoughtcrime.org/software/tortunnel/) or
[`SoaT`](https://gitweb.torproject.org/torflow.git/blob/HEAD:/NetworkScanners/ExitAuthority/README.ExitScanning).

Feedback
--------

Contact: Philipp Winter <phw@nymity.ch>  
OpenPGP fingerprint: `B369 E7A2 18FE CEAD EB96  8C73 CF70 89E3 D7FD C0D0`
