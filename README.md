Prerequisites
-------------

Before you can run `exitmap` you should make sure that you have the
following software installed:

* [stem][]

Within Debian you can install all components by issuing:

    apt-get install python-stem

Retrieve consensus data
-----------------------

First, get the current consensus by running:  
`$ tor -f doc/torrc.fetch`

Then, start the bare Tor process which is used by `exitmap`:  
`$ tor -f doc/torrc`

Run `exitmap`
-------------

Finally, you can run `exitmap`:  
`$ python exitmap.py -c /tmp/tordata/cached-consensus checktest`

[stem]: https://stem.torproject.org/

Feedback
========

Contact: Philipp Winter <phw@nymity.ch>  
OpenPGP fingerprint: `B369 E7A2 18FE CEAD EB96  8C73 CF70 89E3 D7FD C0D0`
