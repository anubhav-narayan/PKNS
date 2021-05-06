'''
PKNS Core Classes and Funtions
'''

__version__ = "0.6.5"
__author__ = "Anubhav Mattoo"

from sqlitedict import SqliteDict
import os
from Crypto.PublicKey import RSA
import socket
import threading
from Cryptor import Cryptor
import Serializer
from hashlib import shake_128
import datetime


def get_constants(prefix):
    '''
    Create a dictionary mapping
    socket module constants to their names.
    '''
    return dict((getattr(socket, n), n)
                for n in dir(socket)
                if n.startswith(prefix))


families = get_constants('AF_')
protocols = get_constants('IPPROTO_')


class PKNS_Table():
    """
    Public Key Name System
    """
    def __init__(self):
        self.peer_table = SqliteDict(os.path.abspath('./pkns.db'),
                                     autocommit=True, tablename='peergroups')
        self.peer_group = 'DEFAULT'
        pass

    def add_user(self, key: str, username: dict,
                 address: list, fingerprint: str) -> None:
        '''
        Add or Update Entry in the Table
        '''
        self.pkns_table = SqliteDict(os.path.abspath('./pkns.db'),
                                     autocommit=True,
                                     tablename=self.peer_group)
        if fingerprint in self.pkns_table and\
           username != self.pkns_table[fingerprint]['username']:
            raise ValueError("Invalid fingerprint")
        if fingerprint in self.pkns_table and\
           username == self.pkns_table[fingerprint]['username']:
            self.add_address(fingerprint, address)
            return
        self.pkns_table[fingerprint] = {
                    'username': username,
                    'address': set([address]),
                    'key': key
                }

    def add_address(self, fingerprint: str, address: tuple) -> None:
        '''
        Add or Update Addresses in the Table
        '''
        self.pkns_table = SqliteDict(os.path.abspath('./pkns.db'),
                                     autocommit=True,
                                     tablename=self.peer_group)
        self.pkns_table[fingerprint]['address'].add(address)

    def remove_address(self, fingerprint: str, address: tuple) -> None:
        '''
        Add or Update Addresses in the Table
        '''
        self.pkns_table = SqliteDict(os.path.abspath('./pkns.db'),
                                     autocommit=True,
                                     tablename=self.peer_group)
        self.pkns_table[fingerprint]['address'].discard(address)

    def purge_user(self, fingerprint: str) -> None:
        '''
        Purge from Table
        '''
        self.pkns_table = SqliteDict(os.path.abspath('./pkns.db'),
                                     autocommit=True,
                                     tablename=self.peer_group)
        if fingerprint not in self.pkns_table:
            raise ValueError("Invalid Key")
        self.pkns_table.pop(fingerprint)

    def add_peergroup(self, peergroup: str,
                      username: str, key_file=None) -> None:
        '''
        Add a Peer Group
        '''
        if peergroup in self.peer_table:
            raise NameError(f'{peergroup} already exists!')
        if key_file is not None:
            key_file = open(key_file, 'rb').read()
        else:
            key = RSA.generate(4096)
            key_public = key.publickey()
            key_file = key_public.export_key()
            master = key.export_key()
            with open(os.path.abspath(f"./master/{shake_128(peergroup.encode('utf8')+ key_file).hexdigest(8)}_MASTER.pem"),
                      'wb') as f:
                f.write(master)
            import stat
            os.chmod(os.path.abspath(f"./master/{shake_128(peergroup.encode('utf8')+ key_file).hexdigest(8)}_MASTER.pem"),
                     0o600)
        self.peer_table[shake_128(peergroup.encode('utf8')
                        + key_file).hexdigest(8)] = {'name': peergroup,
                                                     'address': '0.0.0.0'}
        self.peer_group = shake_128(peergroup.encode('utf8')
                                    + key_file).hexdigest(8)
        self.add_user(key_file, username,
                      '0.0.0.0', shake_128(key_file).hexdigest(8))

    def remove_peergroup(self, peergroup: str):
        '''
        Remove a Peergroup
        '''
        try:
            self.peer_table.pop(peergroup)
            self.pkns_table = SqliteDict(os.path.abspath('./pkns.db'),
                                         autocommit=True, tablename=peergroup)
            self.pkns_table.clear()
            del self.pkns_table
        except KeyError:
            raise Exception(f'Peergroup {peergroup} does not exist')

    def get_peergroup(self, peergroup: str):
        '''
        Peergroup Query
        '''
        if peergroup in self.peer_table:
            return {peergroup: self.peer_table[peergroup]}
        else:
            return {k: v for k, v in self.peer_table.items()
                    if v['name'] == peergroup}

    def get_user(self, peergroup: str, username: str, get_key: bool = False):
        '''
        User Query
        '''
        if peergroup in self.peer_table:
            self.pkns_table = SqliteDict(os.path.abspath('./pkns.db'),
                                         autocommit=True, tablename=peergroup)
            if username in self.pkns_table:
                res = {username: self.pkns_table[username]}
                res[username].pop('key', None)
                self.pkns_table.close()
                res.update(self.peer_table[peergroup])
                return {peergroup: res}
            else:
                res = {k: v for k, v in self.pkns_table.items()
                       if v['username'] == username}
                for x in res:
                    res[x].pop('key', None)
                self.pkns_table.close()
                res.update(self.peer_table[peergroup])
                return {peergroup: res}
        else:
            peergroups = self.get_peergroup(peergroup)
            fres = {}
            for peergroup in peergroups:
                self.pkns_table = SqliteDict(os.path.abspath('./pkns.db'),
                                             autocommit=True,
                                             tablename=peergroup)
                if username in self.pkns_table:
                    res = {username: self.pkns_table[peergroup]}
                    res[username].pop('key', None)
                    self.pkns_table.close()
                    res.update(peergroups[peergroup])
                    fres[peergroup] = res
                else:
                    res = {k: v for k, v in self.pkns_table.items()
                           if v['username'] == username}
                    for x in res:
                        res[x].pop('key', None)
                    self.pkns_table.close()
                    res.update(peergroups[peergroup])
                    fres[peergroup] = res
            return fres

    def resolve(self, query: dict) -> dict:
        '''
        PKNS Query Resolver
        '''
        peergroup = query['peergroup']
        username = query['username']
        if peergroup == '':
            rpeers = {k: v for k, v in self.peer_table.items()}
        else:
            rpeers = self.get_peergroup(peergroup)
        if username == '':
            rusers = {}
        else:
            rusers = self.get_user(peergroup, username)
        response = {}
        rpeers.update(rusers)
        response.update(rpeers)
        return response

    def sync(self, sync: dict) -> None:
        '''
        PKNS Table Sync
        '''
        for x in sync:
            if x in self.peer_table:
                data = self.peer_table[x]
                data.update(sync[x])
                self.peer_table[x] = data
            else:
                self.peer_table[x] = sync[x]


class Base_TCP_Bus():
    """docstring for Base_TCP_Bus"""
    def __init__(self, buffer_size: int = 2048):
        super(Base_TCP_Bus, self).__init__()
        self.buffer_size = buffer_size
        self._serialize = lambda obj: Serializer.to_byte(obj)
        self._deserialize = lambda bytes_: Serializer.to_obj(bytes_)
        self._build_header = lambda size, md5: self._serialize((size, md5))
        self._read_header = lambda header: self._deserialize(header)
        self._build_ack = lambda size, md5: Cryptor.md5((size, md5)).encode()
        self._verify_ack = lambda ack, size, md5: Cryptor.md5((size, md5))\
                                                         .encode() == ack

    # Section From Knight Bus
    def _send_bytes(self, bytes_: bytes):
        try:
            self.socket.send(bytes_)
        except Exception as e:
            raise ConnectionError("Send bytes failed:{}".format(e))

    def _recv_bytes(self, size: int = None):
        try:
            bytes_ = self.socket.recv(size if size is not None
                                      else self.buffer_size)
        except Exception as e:
            raise ConnectionError("Recv bytes failed:{}".format(e))
        return bytes_

    def _send_object_header(self, size, md5):
        try:
            self._send_bytes(self._build_header(size, md5))
            ack = self._recv_bytes()
            if not self._verify_ack(ack, size, md5):
                raise ConnectionError("ACK not matched")
        except Exception as e:
            self.socket.close()
            raise ConnectionAbortedError(
                "FAILED: Connection is unsecured and terminated: {}".format(e)
            )

    def _recv_object_header(self):
        try:
            header = self._recv_bytes()
            size, md5 = self._read_header(header)
            ack = self._build_ack(size, md5)
            self._send_bytes(ack)
        except Exception as e:
            self.socket.close()
            raise ConnectionAbortedError(
                "FAILED: Connection is unsecured and terminated: {}".format(e)
            )
        return size, md5

    def recv(self):
        size, md5 = self._recv_object_header()
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
            if md5 != Cryptor.md5(bytes_):
                raise ConnectionError("Object md5 unmatched")
            else:
                obj = self._deserialize(bytes_)
        except Exception as e:
            self.socket.close()
            raise ConnectionAbortedError(
                "FAILED: Receiving object failed: {}".format(e)
            )
        return obj

    def send(self, obj):
        data = self._serialize(obj)
        self._send_object_header(size=len(data), md5=Cryptor.md5(data))
        self._send_bytes(data)
    # END Sections from Knight Bus


class PKNS_Server(Base_TCP_Bus):
    """docstring for PKNS_Server"""
    def __init__(self, ip_address='0.0.0.0', port: int = 6300):
        super(PKNS_Server, self).__init__()
        self.pool_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.pool_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ip_address = ip_address
        self.port = port

    def serve_endless(self):
        self.pool_sock.bind((self.ip_address, self.port))
        self.pool_sock.listen()
        while True:
            try:
                c, a = self.pool_sock.accept()
                cThread = threading.Thread(target=self.handler, args=(c, a))
                cThread.daemon = True
                cThread.start()
            except KeyboardInterrupt:
                self.pool_sock.close()
                break

    def handler(self, c: socket.socket, a):
        self.socket = c
        pack = self.recv()
        print(f"[{datetime.datetime.now().isoformat(' ')}] {a[0]}@{a[1]}: {pack['tos']}")
        x = PKNS_Response()
        # query handler
        if pack['tos'] == 'PKNS:QUERY':
            table = PKNS_Table()
            x['reply'] = table.resolve(pack['query'])
        if pack['tos'] == 'PKNS:PING':
            # from daemonocle import Daemon
            # x['stats'] = Daemon('PKNS Server',
            #                     pidfile='./PKNS.pid').get_status()
            pass
        if pack['tos'] == 'PKNS:SYNC':
            for i in pack['sync']:
                pack['sync'][i]['address'] = a[0]
            try:
                table = PKNS_Table()
                table.sync(pack['sync'])
                x['reply'] = table.resolve({'peergroup': '', 'username': ''})
            except Exception:
                x['reply'] = 'FAILED'
        x['status'] = 'WORKING'
        x['server'] = socket.gethostbyaddr(self.socket.getsockname()[0])
        x['client'] = a
        x['uproto'] = protocols[c.proto]
        x['transport'] = families[c.family]
        self.send(x)
        self.socket.close()

    def close(self):
        self.pool_sock.close()

    def __del__(self):
        self.close()


class PKNS_Packet_Base(dict):
    """docstring for PKNS_Packet_Base"""
    def __init__(self):
        super(PKNS_Packet_Base, self).__init__()
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


class PKNS_Query(PKNS_Packet_Base):
    """docstring for PKNS_Query"""
    def __init__(self):
        super(PKNS_Query, self).__init__()
        self.__dict__['tos'] = 'PKNS:QUERY'


class PKNS_Response(PKNS_Packet_Base):
    """docstring for PKNS_Response"""
    def __init__(self):
        super(PKNS_Response, self).__init__()
        self.__dict__['tos'] = 'PKNS:RESPONSE'


class PKNS_Ping(PKNS_Packet_Base):
    """docstring for PKNS_Ping"""
    def __init__(self):
        super(PKNS_Ping, self).__init__()
        self.__dict__['tos'] = 'PKNS:PING'


class PKNS_Sync(PKNS_Packet_Base):
    """docstring for PKNS_Sync"""
    def __init__(self):
        super(PKNS_Sync, self).__init__()
        self.__dict__['tos'] = 'PKNS:SYNC'


class PKNS_Request(Base_TCP_Bus):
    """docstring for PKNS_Request"""
    def __init__(self, ip_address='127.0.0.1', port: int = 6300):
        super(PKNS_Request, self).__init__()
        self.ip_address = ip_address
        self.port = port

    def get(self, packet: PKNS_Packet_Base):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.settimeout(30)
        self.socket.connect((self.ip_address, self.port))
        packet['address'] = self.ip_address, self.port
        self.send(packet)
        response = self.recv()
        self.socket.close()
        return response


def parse(query_str: str):
    '''
    Parse PKNS Query to Componenets
    '''
    import re
    ipv4 = r'(?P<ipv4>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'\
           + r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'\
           + r'(?P<port>:[0-9]{,5})?'
    ipv6 = r'(?P<ipv6>'\
           + r'([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'\
           + r'([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}'\
           + r':[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}'\
           + r'(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}'\
           + r'(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}'\
           + r'(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}'\
           + r'(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:'\
           + r'((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|'\
           + r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'\
           + r'::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|'\
           + r'1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|'\
           + r'1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}'\
           + r':((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'\
           + r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
    domain = r'(?P<domain>([a-zA-Z0-9]\.?|[0-9]){,63}(?P<dport>:[0-9]{,5})?))'
    regex = r'^pkns://(?P<base>' + ipv4 + r'|'\
            + ipv6 + r'|'\
            + domain\
            + r'/?'\
            + r'(?P<peergroup>[A-Fa-f0-9]{16}|[A-Za-z0-9]{0,100})?'\
            + r'/?(?P<username>[A-Fa-f0-9]{16}|[A-Za-z0-9]{0,100})?$'
    query = re.match(regex, query_str).groupdict()
    query = {k: v for k, v in query.items()
             if v is not None}
    if query['base'] == '':
        query['base'] = '127.0.0.1:6300'
        query['ipv4'] = '127.0.0.1'
        query['port'] = '6300'
        query.pop('ipv6', None)
        query.pop('domain', None)
    return query
