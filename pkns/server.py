"""
PKNS Server - Network Server Implementation
"""

import os
import socket
import datetime
from concurrent.futures import ThreadPoolExecutor
from daemonocle import Daemon

from .network import BaseUDPBus
from .table import PKNSTable
from .packets import PKNSResponse, PKNSError
from .utils import FAMILIES, PROTOCOLS


class PKNSServer(BaseUDPBus):
    """
    PKNS Server for handling client requests.
    Handles QUERY, PING, and SYNC operations.
    """

    def __init__(self, ip_address='0.0.0.0', port: int = 6300,
                 pkns_path: str = '.pkns', max_workers: int = 10):
        super().__init__()
        self.pool_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.pool_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket = self.pool_sock
        self.ip_address = ip_address
        self.port = port
        self.pkns_path = pkns_path
        self.thread_pool = ThreadPoolExecutor(max_workers=max_workers)

    def serve_endless(self):
        """Start server and listen for incoming datagrams."""
        self.pool_sock.bind((self.ip_address, self.port))
        while True:
            try:
                pack, addr = self.recvfrom()
                self.thread_pool.submit(self.handler, pack, addr)
            except KeyboardInterrupt:
                self.pool_sock.close()
                break

    def handler(self, pack, addr):
        """Handle incoming client requests."""
        print(
            f"[{datetime.datetime.now().isoformat(' ')}] "
            f"{addr[0]}@{addr[1]}: {pack.get('tos', 'UNKNOWN')}"
        )
        try:
            x = PKNSResponse()

            if pack['tos'] == 'PKNS:QUERY':
                table = PKNSTable(self.pkns_path)
                x['reply'] = table.resolve(pack['query'])

            elif pack['tos'] == 'PKNS:PING':
                x['stats'] = Daemon('PKNS Server',
                                   pidfile=os.path.join(
                                       os.environ['HOME'],
                                       self.pkns_path, 'PKNS.pid')).get_status()

            elif pack['tos'] == 'PKNS:SYNC':
                for i in pack['sync']:
                    pack['sync'][i]['address'] = [addr[0]]
                table = PKNSTable(self.pkns_path)
                table.sync(pack['sync'])
                x['reply'] = table.resolve({'peergroup': '', 'username': ''})

            else:
                raise ValueError(f"Unsupported packet type: {pack.get('tos')}")

            x['status'] = 'WORKING'

        except Exception as e:
            print(f"Request handler failed: {e}")
            x = PKNSError()
            x['error'] = str(e)
            x['status'] = 'ERROR'

        x['client'] = addr
        x['protocol'] = PROTOCOLS.get(socket.IPPROTO_UDP, 'IPPROTO_UDP')
        x['transport'] = FAMILIES.get(self.socket.family, 'AF_INET')
        try:
            self.send(x, addr)
        except Exception as send_error:
            print(f"Failed to send response: {send_error}")

    def close(self):
        """Close server socket and shutdown the thread pool."""
        self.pool_sock.close()
        self.thread_pool.shutdown(wait=False)

    def __del__(self):
        self.close()


# Backwards compatibility alias
PKNS_Server = PKNSServer
