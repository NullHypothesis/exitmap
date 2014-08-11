![exitmap logo](https://nullhypothesis.github.com/exitmap_logo.png)

Overview
--------

`exitmap` is a fast and extensible Python-based scanner for
[Tor](https://www.torproject.org) exit relays.  Modules implement tasks which
are then run over all exit relays or a subset thereof.  If you have a
background in functional programming, think of `exitmap` as a `map()` interface
for Tor exit relays.  In practice, `exitmap` is useful to monitor the
reliability and trustworthiness of exit relays.

`exitmap` uses [`Stem`](https://stem.torproject.org) to initiate circuits over
all given exit relays and as soon as `tor` notifies `exitmap` of an established
circuit, a module is invoked for the newly established circuit.

`exitmap` has been used to check for false positives on the Tor Project's
[check](https://check.torproject.org) service and to find [malicious exit
relays](http://www.cs.kau.se/philwint/spoiled_onions).  It is quite easy to
develop new modules for `exitmap`; just have a look at the file HACKING in the
doc/ directory.

Installation
------------

`exitmap` uses the library `Stem` to communicate with Tor.  On Debian jessie
and newer, you can install `Stem` by executing:

    # apt-get install python-stem

Running exitmap
---------------

You can run `exitmap` with the checktest module by executing:

    $ ./bin/exitmap checktest

If you want to use a static first hop, execute:

    $ ./bin/exitmap --first-hop CCEF02AA454C0AB0FE1AC68304F6D8C4220C1912 checktest

To run the same test over German exit relays only, execute:

    $ ./bin/exitmap -C DE --first-hop CCEF02AA454C0AB0FE1AC68304F6D8C4220C1912 checktest

If you want to pause for 5 seconds in between circuits creations in order to
reduce the load on the Tor network and the scanning destination, execute

    $ ./bin/exitmap -d 5 checktest

Note that
[`CCEF02AA454C0AB0FE1AC68304F6D8C4220C1912`](https://atlas.torproject.org/#details/CCEF02AA454C0AB0FE1AC68304F6D8C4220C1912)
is a relay run by Karlstad University.  While you can feel free to use it,
please use your own relays in order to distribute the scanning load.  If you do
not specify a first hop, `exitmap` will randomly select first hops, one for
each circuit.

To get an overview of `exitmap`'s options, execute:

    $ ./bin/exitmap -h

`exitmap` comes with the following modules.

* `testfds`: Tests if an exit relay is able to fetch the content of a simple
  web page.  If an exit relay is unable to do that, it might not have enough
  file descriptors available.
* `checktest`: Attempts to find false positives in the Tor Project's
  [check](https://check.torproject.org) service.
* `dns`: Attempts to resolve several domains and compares the received A
  records to the expected records.

Configuration
-------------

By default, `exitmap` tries to read the file .exitmaprc in your home directory.
The file can have the following format.

    [Defaults]
    first_hop = CCEF02AA454C0AB0FE1AC68304F6D8C4220C1912
    verbosity = debug
    build_delay = 1

Alternatives
------------

Don't like `exitmap`?  Then have a look at
[`tortunnel`](http://www.thoughtcrime.org/software/tortunnel/),
[`SoaT`](https://gitweb.torproject.org/torflow.git/blob/HEAD:/NetworkScanners/ExitAuthority/README.ExitScanning),
[`torscanner`](https://code.google.com/p/torscanner/), or
[`DetecTor`](http://detector.io/DetecTor.html).

Feedback
--------

Contact: Philipp Winter <phw@nymity.ch>  
OpenPGP fingerprint: `B369 E7A2 18FE CEAD EB96  8C73 CF70 89E3 D7FD C0D0`
