"""
PKNS Network - TCP Bus for Network Communication
"""

import socket

from .Signing import Sign
from .Serializer import to_bytes, to_obj


class BaseTCPBus:
    """
    Base class for TCP network communication.
    Handles serialization, deserialization, and packet verification.
    """

    def __init__(self, buffer_size: int = 2048):
        super().__init__()
        self.buffer_size = buffer_size
        self._serialize = lambda obj: to_bytes(obj)
        self._deserialize = lambda bytes_: to_obj(bytes_)
        self._build_header = lambda size, sha256: \
            self._serialize((size, sha256))
        self._read_header = lambda header: self._deserialize(header)
        self._build_ack = lambda size, sha256: \
            Sign.sha256((size, sha256)).encode()
        self._verify_ack = lambda ack, size, sha256: \
            Sign.sha256((size, sha256)).encode() == ack

    def _send_bytes(self, bytes_: bytes):
        """Send raw bytes over socket."""
        try:
            self.socket.send(bytes_)
        except Exception as e:
            raise ConnectionError(f"Send bytes failed: {e}")

    def _recv_bytes(self, size: int = None):
        """Receive raw bytes from socket."""
        try:
            bytes_ = self.socket.recv(size if size is not None
                                      else self.buffer_size)
        except Exception as e:
            raise ConnectionError(f"Recv bytes failed: {e}")
        return bytes_

    def _send_object_header(self, size, sign):
        """Send object header with size and signature."""
        try:
            self._send_bytes(self._build_header(size, sign))
            ack = self._recv_bytes()
            if not self._verify_ack(ack, size, sign):
                raise ConnectionError("ACK not matched")
        except Exception as e:
            self.socket.close()
            raise ConnectionAbortedError(
                f"FAILED: Connection is unsecured and terminated: {e}"
            )

    def _recv_object_header(self):
        """Receive and verify object header."""
        try:
            header = self._recv_bytes()
            size, sign = self._read_header(header)
            ack = self._build_ack(size, sign)
            self._send_bytes(ack)
        except Exception as e:
            self.socket.close()
            raise ConnectionAbortedError(
                f"FAILED: Connection is unsecured and terminated: {e}"
            )
        return size, sign

    def recv(self):
        """Receive and deserialize an object."""
        size, sign = self._recv_object_header()
        try:
            bytes_ = b""
            while size > 0:
                buffer = self._recv_bytes(
                    self.buffer_size if size > self.buffer_size else size
                )
                size -= len(buffer)
                bytes_ += buffer
                if not buffer:
                    break
            if sign != Sign.sha256(bytes_):
                raise ConnectionError("Object sign unmatched")
            obj = self._deserialize(bytes_)
        except Exception as e:
            self.socket.close()
            raise ConnectionAbortedError(
                f"FAILED: Receiving object failed: {e}"
            )
        return obj

    def send(self, obj):
        """Serialize and send an object."""
        data = self._serialize(obj)
        self._send_object_header(size=len(data), sign=Sign.sha256(data))
        self._send_bytes(data)


class BaseUDPBus:
    """
    Base class for UDP network communication.
    Handles serialization, deserialization, and packet verification
    with a single datagram per object.
    """

    def __init__(self, buffer_size: int = 2048):
        super().__init__()
        self.buffer_size = buffer_size
        self.remote_addr = None
        self._serialize = lambda obj: to_bytes(obj)
        self._deserialize = lambda bytes_: to_obj(bytes_)

    def _send_bytes(self, bytes_: bytes, addr=None):
        """Send raw bytes over UDP."""
        try:
            if addr is not None:
                self.socket.sendto(bytes_, addr)
            else:
                self.socket.send(bytes_)
        except Exception as e:
            raise ConnectionError(f"Send bytes failed: {e}")

    def _recv_bytes(self, size: int = None):
        """Receive raw bytes from UDP."""
        try:
            bytes_, addr = self.socket.recvfrom(
                size if size is not None else self.buffer_size
            )
        except Exception as e:
            raise ConnectionError(f"Recv bytes failed: {e}")
        return bytes_, addr

    def _build_message(self, payload: bytes) -> bytes:
        return Sign.sha256(payload).encode() + b'|' + payload

    def _parse_message(self, message: bytes) -> bytes:
        try:
            sign, payload = message.split(b'|', 1)
        except ValueError:
            raise ConnectionError("Invalid UDP message format")
        if sign != Sign.sha256(payload).encode():
            raise ConnectionError("Object sign unmatched")
        return payload

    def recv(self):
        """Receive and deserialize an object from a connected UDP socket."""
        message, addr = self._recv_bytes()
        if self.remote_addr is None:
            self.remote_addr = addr
        return self._deserialize(self._parse_message(message))

    def recvfrom(self):
        """Receive and deserialize an object from UDP and return the sender address."""
        message, addr = self._recv_bytes()
        return self._deserialize(self._parse_message(message)), addr

    def send(self, obj, addr=None):
        """Serialize and send an object over UDP."""
        data = self._serialize(obj)
        message = self._build_message(data)
        if addr is None and self.remote_addr is None:
            raise ConnectionError("No destination address for UDP send")
        self._send_bytes(message, addr or self.remote_addr)


# Backwards compatibility alias
Base_TCP_Bus = BaseTCPBus
Base_UDP_Bus = BaseUDPBus
