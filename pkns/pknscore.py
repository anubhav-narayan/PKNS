"""
PKNS Core - Backwards Compatibility Module

This module re-exports classes and functions from refactored submodules
for backwards compatibility with existing code.
"""

__version__ = "0.6.0"
__author__ = "Anubhav Mattoo"
__email__ = "anubhavmattoo@outlook.com"
__license__ = "AGPLv3"
__status__ = "Public Beta"

# Import utilities
from .utils import dict_merge, get_constants, FAMILIES, PROTOCOLS

# Import tables
from .table import PKNSTable, PKNS_Table

# Import packets
from .packets import (
    PKNSPacketBase, PKNS_Packet_Base,
    PKNSQuery, PKNS_Query,
    PKNSResponse, PKNS_Response,
    PKNSPing, PKNS_Ping,
    PKNSSync, PKNS_Sync
)

# Import network
from .network import BaseTCPBus, BaseUDPBus, Base_TCP_Bus, Base_UDP_Bus

# Import server
from .server import PKNSServer, PKNS_Server

# Import client
from .client import PKNSRequest, PKNS_Request, parse

# Backwards compatibility alias for constants
FAMALIES = FAMILIES

__all__ = [
    'dict_merge', 'get_constants', 'FAMILIES', 'PROTOCOLS', 'FAMALIES',
    'PKNSTable', 'PKNS_Table',
    'PKNSPacketBase', 'PKNS_Packet_Base',
    'PKNSQuery', 'PKNS_Query',
    'PKNSResponse', 'PKNS_Response',
    'PKNSPing', 'PKNS_Ping',
    'PKNSSync', 'PKNS_Sync',
    'BaseTCPBus', 'BaseUDPBus', 'Base_TCP_Bus', 'Base_UDP_Bus',
    'PKNSServer', 'PKNS_Server',
    'PKNSRequest', 'PKNS_Request',
    'parse',
]

