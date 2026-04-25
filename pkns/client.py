"""
PKNS Client - Client Request Implementation
"""

import re
import socket

from .network import BaseUDPBus
from .packets import PKNSPacketBase


class PKNSRequest(BaseUDPBus):
    """
    PKNS Client for sending requests to a PKNS server.
    """

    def __init__(self, ip_address='127.0.0.1', port: int = 6300):
        super().__init__()
        self.ip_address = ip_address
        self.port = port

    def get(self, packet: PKNSPacketBase):
        """Send a packet to the server and receive response."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.settimeout(30)
        try:
            self.socket.connect((self.ip_address, self.port))
            self.remote_addr = (self.ip_address, self.port)
            self.send(packet)
            response = self.recv()
        except socket.timeout:
            raise ConnectionError('Connection Timeout')
        self.socket.close()
        return response


def parse(query_str: str):
    """
    Parse PKNS query string to components.
    
    Query format: pkns://HOST_SERVER[:PORT][/PEERGROUP][/USER]
    """
    ipv4 = (
        r'(?P<ipv4>('
        r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
        r'(?P<port>:[0-9]{1,5})?'
    )

    ipv6 = (
        r'(?P<ipv6>('
        r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
        r'([0-9a-fA-F]{1,7}:)|'
        r'([0-9a-fA-F]{1,6}:[0-9a-fA-F]{1,4})|'
        r'([0-9a-fA-F]{1,5}(:[0-9a-fA-F]{1,4}){1,2})|'
        r'([0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){1,3})|'
        r'([0-9a-fA-F]{1,3}(:[0-9a-fA-F]{1,4}){1,4})|'
        r'([0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,4}){1,5})|'
        r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
        r':((:[0-9a-fA-F]{1,4}){1,7}|:)|'
        r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9A-Za-z]{1,}|'
        r'::(ffff(:0{1,4})?:)?'
        r'((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}'
        r'(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|'
        r'([0-9a-fA-F]{1,4}:){1,4}:'
        r'((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}'
        r'(25[0-5]|(2[0-4]|1?[0-9])?[0-9])'
        r'))'
    )

    domain = (
        r'(?P<domain>('
        r'([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}'
        r'))(?P<dport>:[0-9]{1,5})?'
    )

    regex = (
        r'^pkns://(?P<base>('
        + ipv4 + r'|'
        + ipv6 + r'|'
        + domain +
        r'))/?'
        r'(?P<peergroup>[A-Fa-f0-9]{16}|[^\s\/\\.,$]{0,100})?'
        r'/?(?P<username>[A-Fa-f0-9]{16}|[^\s\/\\.,$]{0,100})?$'
    )

    
    query = re.match(regex, query_str).groupdict()
    query = {k: v for k, v in query.items() if v is not None}
    
    if query['base'] == '':
        query['base'] = '127.0.0.1:6300'
        query['ipv4'] = '127.0.0.1'
        query['port'] = ':6300'
        query.pop('ipv6', None)
        query.pop('domain', None)
    
    return query


# Backwards compatibility aliases
PKNS_Request = PKNSRequest
