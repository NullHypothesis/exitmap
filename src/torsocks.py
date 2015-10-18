# Copyright 2015 Philipp Winter <phw@nymity.ch>
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

"""
Provide a Tor-specific SOCKSv5 interface.
"""

import struct
import socket

import error
import log

logger = log.get_logger()

proxy_addr = None
proxy_port = None
queue = None
circ_id = None

orig_socket = socket.socket

# Server-side SOCKSv5 errors.
socks5_errors = {
    0x00: "Request granted",
    0x01: "General failure",
    0x02: "Connection not allowed by ruleset",
    0x03: "Network unreachable",
    0x04: "Host unreachable",
    0x05: "Connection refused by destination host",
    0x06: "TTL expired",
    0x07: "Command not supported / protocol error",
    0x08: "Address type not supported",
}

def send_queue(sock_name):
    """
    Inform caller about our newly created socket.

    We need to temporarily use the original socket.socket implementation for
    the queue to work.
    """

    global queue, circ_id, orig_socket
    assert (queue is not None) and (circ_id is not None)

    tmp_socket = socket.socket
    socket.socket = orig_socket

    queue.put([circ_id, sock_name])

    socket.socket = tmp_socket


def set_default_proxy(ip_addr, port):
    """
    Set the SOCKS proxy address and its port.
    """

    global proxy_addr, proxy_port
    proxy_addr, proxy_port = ip_addr, port


class torsocket(socket.socket):

    """
    Provides a minimal, Tor-specific SOCKSv5 interface.
    """

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM,
                 proto=0, _sock=None):

        self.sockfamily = family
        self.socktype = type

        super(torsocket, self).__init__(family, type, proto, _sock)

    def _authenticate(self):
        """
        Authenticate to our SOCKSv5 server.
        """

        assert (proxy_addr is not None) and (proxy_port is not None)

        # Connect to SOCKSv5 server.  We use version 5 and one authentication
        # method, which is "no authentication".

        orig_socket.connect(self, (proxy_addr, proxy_port))

        self.sendall("\x05\x01\x00")

        resp = self.recv(2)
        if resp != "\x05\x00":
            raise error.SOCKSv5Error("Invalid server response: 0x%s" %
                                     resp.encode("hex"))

        send_queue(self.getsockname())

    def resolve(self, domain):
        """
        Resolve the given domain using Tor's SOCKS resolution extension.
        """

        domain_len = len(domain)
        if domain_len > 255:
            raise error.SOCKSv5Error("Domain must not be longer than 255 "
                                     "characters, but %d given." % domain_len)

        # Tor defines a new command value, \x0f, that is used for domain
        # resolution.

        self._authenticate()
        self.sendall("\x05\xf0\x00\x03%s%s%s" %
                     (chr(domain_len), domain, "\x00\x00"))

        resp = self.recv(10)
        if resp[:2] != "\x05\x00":
            raise error.SOCKSv5Error("Invalid server response: 0x%s" %
                                     resp[1].encode("hex"))

        return socket.inet_ntoa(resp[4:8])

    def connect(self, addr_tuple):
        """
        Tell SOCKS server to connect to our destination.
        """

        dst_addr, dst_port = addr_tuple[0], int(addr_tuple[1])

        self._authenticate()

        # Tell SOCKS server to connect to destination.

        self.sendall("\x05\x01\x00\x01%s%s" %
                     (socket.inet_aton(dst_addr), struct.pack(">H", dst_port)))

        resp = self.recv(4)
        if resp[1] != "\x00":
            val = int(resp[1].encode("hex"), 16)
            if 0 <= val < len(socks5_errors):
                raise error.SOCKSv5Error("SOCKSv5 connection failed because: "
                                         "%s" % socks5_errors[val])
            else:
                raise error.SOCKSv5Error("Unexpected SOCKSv5 error: %d" % val)

        # Depending on address type, get address.

        if resp[3] == "\x01":
            self.recv(4)
        elif resp[3] == "\x03":
            length = self.recv(1)
            self.recv(length)
        else:
            self.recv(16)

        # Get port.

        self.recv(2)
