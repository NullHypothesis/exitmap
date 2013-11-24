Installation
============

You will need the library [stem](https://stem.torproject.org).

First, get the current consensus by running:  
`$ tor -f doc/torrc.fetch`

Then, start the bare Tor process which is used by the scanner:  
`$ tor -f doc/torrc`

Finally, you can run the scanner:  
`$ python scanner.py -c /tmp/tordata/cached-consensus checktest`

Feedback
========

Contact: Philipp Winter <phw@nymity.ch>  
OpenPGP fingerprint: `B369 E7A2 18FE CEAD EB96  8C73 CF70 89E3 D7FD C0D0`
