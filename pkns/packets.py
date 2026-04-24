"""
PKNS Packet Classes for Protocol Communication
"""


class PKNSPacketBase(dict):
    """
    Base class for PKNS packets. Provides dict-like interface
    with internal __dict__ storage.
    """

    def __init__(self):
        super().__init__()
        self.__dict__['tos'] = 'PKNS:GENERAL'

    def __setitem__(self, key, item):
        self.__dict__[key] = item

    def __getitem__(self, key):
        return self.__dict__[key]

    def __repr__(self):
        return repr(self.__dict__)

    def __len__(self):
        return len(self.__dict__)

    def __delitem__(self, key):
        del self.__dict__[key]

    def clear(self):
        return self.__dict__.clear()

    def copy(self):
        return self.__dict__.copy()

    def has_key(self, k):
        return k in self.__dict__

    def update(self, *args, **kwargs):
        return self.__dict__.update(*args, **kwargs)

    def keys(self):
        return self.__dict__.keys()

    def values(self):
        return self.__dict__.values()

    def items(self):
        return self.__dict__.items()

    def pop(self, *args):
        return self.__dict__.pop(*args)

    def __cmp__(self, other):
        return self.__cmp__(self.__dict__, other)

    def __contains__(self, item):
        return item in self.__dict__

    def __iter__(self):
        return iter(self.__dict__)

    def __unicode__(self):
        return unicode(repr(self.__dict__))


class PKNSQuery(PKNSPacketBase):
    """PKNS Query packet for requesting information."""

    def __init__(self):
        super().__init__()
        self.__dict__['tos'] = 'PKNS:QUERY'


class PKNSResponse(PKNSPacketBase):
    """PKNS Response packet for returning query results."""

    def __init__(self):
        super().__init__()
        self.__dict__['tos'] = 'PKNS:RESPONSE'


class PKNSError(PKNSPacketBase):
    """PKNS Error packet for returning failure details."""

    def __init__(self):
        super().__init__()
        self.__dict__['tos'] = 'PKNS:ERROR'
        self.__dict__['error'] = ''
        self.__dict__['status'] = 'ERROR'


class PKNSPing(PKNSPacketBase):
    """PKNS Ping packet for server status checks."""

    def __init__(self):
        super().__init__()
        self.__dict__['tos'] = 'PKNS:PING'


class PKNSSync(PKNSPacketBase):
    """PKNS Sync packet for table synchronization."""

    def __init__(self):
        super().__init__()
        self.__dict__['tos'] = 'PKNS:SYNC'


# Backwards compatibility aliases
PKNS_Packet_Base = PKNSPacketBase
PKNS_Query = PKNSQuery
PKNS_Response = PKNSResponse
PKNS_Ping = PKNSPing
PKNS_Sync = PKNSSync
