from jsonpickle import encode, decode
from .signing import Sign
import socket


class Base_TCP_Bus():
    """
    Base Class for TCP Busses Used
    """
    def __init__(self, buffer_size: int = 2048):
        super(Base_TCP_Bus, self).__init__()
        self.buffer_size = buffer_size
        self._serialize = lambda obj: encode(obj).encode()
        self._deserialize = lambda bytes_: decode(bytes_.decode())
        self._build_header = lambda size, sha256:\
            self._serialize((size, sha256))
        self._read_header = lambda header: self._deserialize(header)
        self._build_ack = lambda size, sha256:\
            Sign.sign(
                self._serialize((size, sha256)), Sign.sha256
            ).encode()
        self._verify_ack = lambda ack, size, sha256:\
            Sign.sign(
                self._serialize((size, sha256)), Sign.sha256
            ).encode() == ack

    # Section From Knight Bus
    def _send_bytes(self, bytes_: bytes):
        try:
            self.socket.send(bytes_)
        except Exception as e:
            raise ConnectionError(f"Send bytes failed:{e}")

    def _recv_bytes(self):
        try:
            bytes_ = self.socket.recv(self.buffer_size)
        except Exception as e:
            raise ConnectionError(f"Recv bytes failed:{e}")
        return bytes_

    def _send_object_header(self, size, sign):
        try:
            header = self._build_header(size, sign)
            self._send_bytes(header)
            ack = self._recv_bytes()
            if not self._verify_ack(ack, size, sign):
                raise ConnectionError("ACK Error")
        except Exception as e:
            self.socket.close()
            raise ConnectionAbortedError(
                f"FAILED: {e}"
            )

    def _recv_object_header(self):
        try:
            header = self._recv_bytes()
            size, sign = self._read_header(header)
            ack = self._build_ack(size, sign)
            self._send_bytes(ack)
        except Exception as e:
            self.socket.close()
            raise ConnectionAbortedError(
                f"FAILED: {e}"
            )
        return size, sign

    def recv(self):
        size, sign = self._recv_object_header()
        try:
            bytes_ = b""
            while size > 0:
                buffer = self._recv_bytes()
                size -= len(buffer)
                bytes_ += buffer
                if not buffer:
                    break
            if sign != Sign.sha256(bytes_):
                raise ConnectionError("Object sign unmatched")
            else:
                obj = self._deserialize(bytes_)
        except Exception as e:
            self.socket.close()
            raise ConnectionAbortedError(
                f"FAILED: Receiving object failed: {e}"
            )
        return obj

    def send(self, obj):
        data = self._serialize(obj)
        self._send_object_header(size=len(data), sign=Sign.sha256(data))
        self._send_bytes(data)
    # END Sections from Knight Bus
