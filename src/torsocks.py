# Copyright 2015, 2016 Philipp Winter <phw@nymity.ch>
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

import os
import struct
import socket
import select
import errno
import logging

import error

log = logging.getLogger(__name__)

proxy_addr = None
proxy_port = None
queue      = None
circ_id    = None

orig_socket = socket.socket

_ERRNO_RETRY = frozenset((errno.EAGAIN, errno.EWOULDBLOCK,
                          errno.EINPROGRESS, errno.EINTR))

_LOCAL_SOCKETS = frozenset(
    getattr(socket, af) for af in [
        'AF_UNIX', 'AF_LOCAL',
        'AF_ROUTE', 'AF_KEY', 'AF_ALG', 'AF_NETLINK'
    ]
    if hasattr(socket, af)
)

# Fix PyPy 2.6.1 issue that Travis CI found.
if not hasattr(errno, "ENOTSUP"):
    errno.ENOTSUP = 95

# Map server-side SOCKSv5 errors to errno codes (as best we can; codes
# 1 and 7 don't correspond to documented error codes for connect(2))
socks5_errors = {
    0x00: 0,                   # Success
    0x01: errno.EIO,           # General failure
    0x02: errno.EACCES,        # Connection not allowed by ruleset
    0x03: errno.ENETUNREACH,   # Network unreachable
    0x04: errno.EHOSTUNREACH,  # Host unreachable
    0x05: errno.ECONNREFUSED,  # Connection refused by destination host
    0x06: errno.ETIMEDOUT,     # TTL expired
    0x07: errno.ENOTSUP,       # Command not supported / protocol error
    0x08: errno.EAFNOSUPPORT,  # Address type not supported
}


def send_queue(sock_name):
    """
    Inform caller about our newly created socket.
    """

    global queue, circ_id
    assert (queue is not None) and (circ_id is not None)

    queue.put([circ_id, sock_name])


class _Torsocket(orig_socket):

    """
    Provides a minimal, Tor-specific SOCKSv5 interface.
    """

    # Implementation note: socket.socket is (at least in Python 2) a
    # wrapper object around _socket.socket. Most superclass methods
    # cannot be invoked via the usual super().method(self, args...)
    # construct.  One must use self._sock.method(args...) instead.

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM,
                 proto=0, _sock=None):

        self._sockfamily = family
        self._socktype   = type
        self._connecting = False
        self._connected  = False
        self._peer_addr  = None
        self._conn_err   = None

        super(_Torsocket, self).__init__(family, type, proto, _sock)

        # FIXME: Arguably this should happen only on connect() so that
        # attempts to connect to 127.0.0.1 can bypass the proxy server.
        # However, that would make nonblocking mode significantly more
        # complicated.  We'd need an actual state machine instead of
        # just a pair of booleans, and callers would need to be
        # prepared to 'turn the crank' on the state machine.
        self._authenticate()

    def _recv_all(self, num_bytes):
        """
        Try to read the given number of bytes, blocking indefinitely
        if necessary (even if the socket is in nonblocking mode).

        If we are unable to read all of it, an EOFError is raised.
        """

        data = ""
        while len(data) < num_bytes:
            try:
                more = self._sock.recv(num_bytes - len(data))
            except socket.error as e:
                if e.errno not in _ERRNO_RETRY:
                    raise

                select.select([self], [], [])
                continue

            if not more:
                raise EOFError("Could read only %d of expected %d bytes." %
                               (len(data), num_bytes))
            data += more

        return data

    def _send_all(self, msg):
        """
        Try to send all of 'msg', blocking indefinitely if necessary
        (even if the socket is in nonblocking mode).
        """

        sent = 0
        while sent < len(msg):
            try:
                n = self._sock.send(msg[sent:])
            except socket.error as e:
                if e.errno not in _ERRNO_RETRY:
                    raise

                select.select([], [self], [])
                continue

            if not n:
                raise EOFError("Could send only %d of expected %d bytes." %
                               (sent, len(msg)))
            sent += n

    def _authenticate(self):
        """
        Authenticate to our SOCKSv5 server.
        """

        assert (proxy_addr is not None) and (proxy_port is not None)

        # Connect to SOCKSv5 server.  We use version 5 and one authentication
        # method, which is "no authentication".

        self._sock.connect((proxy_addr, proxy_port))
        self._send_all("\x05\x01\x00")
        resp = self._recv_all(2)
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

        self._send_all("\x05\xf0\x00\x03%s%s%s" %
                     (chr(domain_len), domain, "\x00\x00"))

        resp = self._recv_all(10)
        if resp[:2] != "\x05\x00":
            raise error.SOCKSv5Error("Invalid server response: 0x%s" %
                                     resp[1].encode("hex"))

        return socket.inet_ntoa(resp[4:8])

    def connect(self, addr_tuple):
        err = self.connect_ex(addr_tuple)
        if err:
            raise socket.error(err, os.strerror(err))

    def connect_ex(self, addr_tuple):
        """
        Tell SOCKS server to connect to our destination.
        """

        dst_addr, dst_port = addr_tuple[0], int(addr_tuple[1])
        self._connecting = True
        self._peer_addr = (dst_addr, dst_port)

        log.debug("Requesting connection to %s:%d.", dst_addr, dst_port)

        self._send_all("\x05\x01\x00\x01%s%s" %
                     (socket.inet_aton(dst_addr), struct.pack(">H", dst_port)))

        return self._attempt_finish_socks_handshake()

    def _attempt_finish_socks_handshake(self):
        # Receive the first byte of the server reply using the
        # underlying recv() primitive, and suspend this operation if
        # it comes back with EAGAIN, or fail it if it gives an error.
        # Callers of connect_ex expect to get EINPROGRESS, not EAGAIN.
        log.debug("Attempting to read SOCKS reply.")
        try:
            resp0 = self._sock.recv(1)
        except socket.error as e:
            if e.errno in _ERRNO_RETRY:
                log.debug("SOCKS reply not yet available.")
                return errno.EINPROGRESS

            log.debug("Connection failure: %s", e)
            self._connecting = False
            self._conn_err = e.errno
            return e.errno

        if resp0 != "\x05":
            self._connecting = False
            raise error.SOCKSv5Error(
                "Protocol error: server reply begins with 0x%02x, not 0x05"
                % ord(resp0))

        # We are now committed to receiving and processing the server
        # response.
        resp = self._recv_all(3)
        if resp[0] != "\x00":
            self._connecting = False
            val = ord(resp[0])
            if val in socks5_errors:
                self._conn_err = socks5_errors[val]
                log.debug("Connection failure at protocol level: %s",
                          os.strerror(self._conn_err))
                return self._conn_err
            else:
                raise error.SOCKSv5Error("Unrecognized SOCKSv5 error: %d" % val)

        # Read and discard the rest of the reply, which consists of an
        # address type (1 byte), variable-length address (depending on the
        # address type), and port number (2 bytes).
        if resp[2] == "\x01":
            self._recv_all(4)
        elif resp[2] == "\x03":
            length = self._recv_all(1)
            self._recv_all(ord(length))
        else:
            self._recv_all(16)
        self._recv_all(2)

        # We are now officially connected.
        log.debug("Now connected to %s:%d.", *self._peer_addr)
        self._connected = True
        return 0

    def _maybe_finish_socks_handshake(self):
        if self._connected:
            return
        if not self._connecting:
            raise socket.error(errno.ENOTCONN, os.strerror(errno.ENOTCONN))

        err = self._attempt_finish_socks_handshake()
        if err:
            # Callers of _this_ function expect EAGAIN, not EINPROGRESS.
            if err in _ERRNO_RETRY:
                raise socket.error(errno.EAGAIN, os.strerror(errno.EAGAIN))
            raise socket.error(err, os.strerror(err))

    # All of these functions must be prepared to process the final
    # message of the SOCKS handshake.
    def send(self, *args):
        self._maybe_finish_socks_handshake()
        return self._sock.send(*args)

    def sendall(self, *args):
        self._maybe_finish_socks_handshake()
        return self._sock.sendall(*args)

    def recv(self, *args):
        self._maybe_finish_socks_handshake()
        return self._sock.recv(*args)

    def recv_into(self, *args):
        self._maybe_finish_socks_handshake()
        return self._sock.recv_into(*args)

    def makefile(self, *args):
        # This one is a normal method on socket.socket.
        self._maybe_finish_socks_handshake()
        return super(_Torsocket, self).makefile(*args)

    # These sockets can only be used as client sockets.
    def accept(self): raise NotImplementedError

    def bind(self): raise NotImplementedError

    def listen(self): raise NotImplementedError

    # These sockets can only be used as connected sockets.
    def sendto(self, *a): raise NotImplementedError

    def recvfrom(self, *a): raise NotImplementedError

    def recvfrom_into(self, *a): raise NotImplementedError

    # Provide information about the ultimate destination, not the
    # proxy server.  On normal sockets, getpeername() works immediately
    # after connect(), even if it returned EINPROGRESS.
    def getpeername(self):
        if not self._connecting:
            raise socket.error(errno.ENOTCONN, os.strerror(errno.ENOTCONN))
        return self._peer_addr

    # Provide the pending connection error if appropriate.
    def getsockopt(self, level, opt, *args):
        if level == socket.SOL_SOCKET and opt == socket.SO_ERROR:
            if self._connecting:
                err = self._attempt_finish_socks_handshake()
                if err == errno.EINPROGRESS:
                    return 0  # there's no pending connection error yet

            if self._conn_err is not None:
                err = self._conn_err
                self._conn_err = None
                return err

        return self._sock.getsockopt(level, opt, *args)


def torsocket(family=socket.AF_INET, type=socket.SOCK_STREAM,
              proto=0, _sock=None):
    """
    Factory function usable as a monkey-patch for socket.socket.
    """

    # Pass through local sockets.
    if family in _LOCAL_SOCKETS:
        return orig_socket(family, type, proto, _sock)

    # Tor only supports AF_INET sockets.
    if family != socket.AF_INET:
        raise socket.error(errno.EAFNOSUPPORT, os.strerror(errno.EAFNOSUPPORT))

    # Tor only supports SOCK_STREAM sockets.
    if type != socket.SOCK_STREAM:
        raise socket.error(errno.ESOCKTNOSUPPORT,
                           os.strerror(errno.ESOCKTNOSUPPORT))

    # Acceptable values for PROTO are 0 and IPPROTO_TCP.
    if proto not in (0, socket.IPPROTO_TCP):
        raise socket.error(errno.EPROTONOSUPPORT,
                           os.strerror(errno.EPROTONOSUPPORT))

    return _Torsocket(family, type, proto, _sock)


class MonkeyPatchedSocket(object):
    """
    Context manager which monkey-patches socket.socket with
    the above torsocket().  It also sets up this module's
    global state.
    """
    def __init__(self, queue, circ_id, socks_port, socks_addr="127.0.0.1"):
        self._queue           = queue
        self._circ_id         = circ_id
        self._socks_addr      = socks_addr
        self._socks_port      = socks_port

        self._orig_queue      = None
        self._orig_circ_id    = None
        self._orig_proxy_addr = None
        self._orig_proxy_port = None
        self._orig_socket     = None

    def __enter__(self):
        global queue, circ_id, proxy_addr, proxy_port, socket, torsocket

        # Make sure __exit__ can put everything back just as it was.
        self._orig_queue      = queue
        self._orig_circ_id    = circ_id
        self._orig_proxy_addr = proxy_addr
        self._orig_proxy_port = proxy_port
        self._orig_socket     = socket.socket

        queue                 = self._queue
        circ_id               = self._circ_id
        proxy_addr            = self._socks_addr
        proxy_port            = self._socks_port
        socket.socket         = torsocket

        return self

    def __exit__(self, *dontcare):
        global queue, circ_id, proxy_addr, proxy_port, socket

        queue                 = self._orig_queue
        circ_id               = self._orig_circ_id
        proxy_addr            = self._orig_proxy_addr
        proxy_port            = self._orig_proxy_port
        socket.socket         = self._orig_socket

        return False
