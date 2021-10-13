'''
PKNS Core Classes and Funtions
'''


from sqlitedict import SqliteDict
import os
from Crypto.PublicKey import RSA
import socket
import threading
from .signing import Sign
from .transport import Base_TCP_Bus
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


FAMALIES = get_constants('AF_')
PROTOCOLS = get_constants('IPPROTO_')


def dict_merge(a, b):
    '''
    Recursive Dict Merge
    '''
    from copy import deepcopy
    if not isinstance(b, dict):
        return b
    result = deepcopy(a)
    for k, v in b.items():
        if k in result and isinstance(result[k], dict):
            result[k] = dict_merge(result[k], v)
        else:
            result[k] = deepcopy(v)
    return result


class PKNS_Table():
    """
    Public Key Name System
    """
    def __init__(self, path: str = '.pkns'):
        self.path = path
        if not os.path.exists(os.path.join(os.environ['HOME'], self.path)):
            os.mkdir(os.path.join(os.environ['HOME'], self.path))
        self.peer_table = SqliteDict(os.path.join(
                                     os.environ['HOME'],
                                     path, 'pkns.db'),
                                     autocommit=True, tablename='peergroups')
        pass

    def add_user(self, key: bytes, username: str,
                 address: tuple, fingerprint: str,
                 peergroup: str) -> None:
        '''
        Add or Update Entry in the Table
        '''
        self.pkns_table = SqliteDict(os.path.join(
                                     os.environ['HOME'],
                                     self.path, 'pkns.db'),
                                     autocommit=True,
                                     tablename=peergroup)
        if fingerprint in self.pkns_table and\
           username != self.pkns_table[fingerprint]['username']:
            raise ValueError("Invalid Fingerprint")
        if fingerprint in self.pkns_table and\
           username == self.pkns_table[fingerprint]['username']:
            self.pkns_table.close()
            self.add_address(fingerprint, address, peergroup)
            return
        self.pkns_table[fingerprint] = {
                    'username': username,
                    'address': address if type(address) is set
                    else set(address),
                    'key': key
                }
        self.pkns_table.close()

    def add_address(self, fingerprint: str, address: tuple,
                    peergroup: str) -> None:
        '''
        Add or Update Addresses in the Table
        '''
        self.pkns_table = SqliteDict(os.path.join(
                                     os.environ['HOME'],
                                     self.path, 'pkns.db'),
                                     autocommit=True,
                                     tablename=peergroup)
        if type(address) is set:
            self.pkns_table[fingerprint]['address'].update(address)
        else:
            self.pkns_table[fingerprint]['address'].update(set(address))
        self.pkns_table.close()

    def remove_address(self, fingerprint: str, address: tuple,
                       peergroup: str) -> None:
        '''
        Add or Update Addresses in the Table
        '''
        self.pkns_table = SqliteDict(os.path.join(
                                     os.environ['HOME'],
                                     self.path, 'pkns.db'),
                                     autocommit=True,
                                     tablename=peergroup)
        self.pkns_table[fingerprint]['address'].discard(address)
        self.pkns_table.close()

    def purge_user(self, fingerprint: str, peergroup: str) -> None:
        '''
        Purge from Table
        '''
        if peergroup not in self.peer_table:
            raise ValueError("Invalid Peergroup")
        self.pkns_table = SqliteDict(os.path.join(
                                     os.environ['HOME'],
                                     self.path, 'pkns.db'),
                                     autocommit=True,
                                     tablename=peergroup)
        if fingerprint not in self.pkns_table:
            raise ValueError("Invalid Key")
        self.pkns_table.pop(fingerprint)
        self.pkns_table.close()

    def add_peergroup(self, peergroup: str,
                      username: str, key_file=None,
                      rsa_size: int = 3072,
                      get_master: bool = False) -> None or str:
        '''
        Add a Peer Group
        '''
        if peergroup in self.peer_table:
            raise NameError(f'{peergroup} already exists!')
        if key_file is None:
            key = RSA.generate(rsa_size)
            key_public = key.publickey()
            key_file = key_public.export_key()
            master = key.export_key()
            fingerprint = shake_128(peergroup.encode('utf8') + key_file)\
                .hexdigest(8)
            with open(os.path.join(os.environ['HOME'],
                      f"{self.path}", "master", f"{fingerprint}_MASTER.pem"),
                      'wb') as f:
                f.write(master)
            import stat
            os.chmod(os.path.join(os.environ['HOME'],
                     f"{self.path}", "master", f"{fingerprint}_MASTER.pem"),
                     0o600)
        self.peer_table[shake_128(peergroup.encode('utf8')
                        + key_file).hexdigest(8)] = {'name': peergroup,
                                                     'address': {'0.0.0.0', }}
        self.add_user(key_file, username,
                      '0.0.0.0', shake_128(key_file).hexdigest(8),
                      shake_128(peergroup.encode('utf8')
                                + key_file).hexdigest(8))
        if get_master:
            try:
                return key.export_key()
            except Exception:
                return None

    def remove_peergroup(self, peergroup: str):
        '''
        Remove a Peergroup
        '''
        try:
            self.peer_table.pop(peergroup)
            self.pkns_table = SqliteDict(os.path.join(
                                    os.environ['HOME'],
                                    self.path, 'pkns.db'),
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

    def rename_peergroup(self, peergroup: str, new_name: str) -> None:
        '''
        Peergroup Rename
        '''
        if peergroup not in self.peer_table:
            raise ValueError(
                f'Peergroup {peergroup} not found')
        peergroup_ = self.peer_table[peergroup]
        peergroup_['name'] = new_name
        self.peer_table[peergroup] = peergroup_

    def get_user(self, peergroup: str, username: str, get_key: bool = False):
        '''
        User Query
        '''
        if peergroup in self.peer_table:
            self.pkns_table = SqliteDict(os.path.join(
                                     os.environ['HOME'],
                                     self.path, 'pkns.db'),
                                     autocommit=True, tablename=peergroup)
            if username in self.pkns_table:
                res = {username: self.pkns_table[username]}
                if not get_key:
                    res[username].pop('key', None)
                self.pkns_table.close()
                res.update(self.peer_table[peergroup])
                return {peergroup: res}
            else:
                res = {k: v for k, v in self.pkns_table.items()
                       if v['username'] == username}
                if not get_key:
                    for x in res:
                        res[x].pop('key', None)
                self.pkns_table.close()
                res.update(self.peer_table[peergroup])
                return {peergroup: res}
        else:
            peergroups = self.get_peergroup(peergroup)
            fres = {}
            for peergroup in peergroups:
                self.pkns_table = SqliteDict(os.path.join(
                                     os.environ['HOME'],
                                     self.path, 'pkns.db'),
                                    autocommit=True,
                                    tablename=peergroup)
                if username in self.pkns_table:
                    res = {username: self.pkns_table[username]}
                    if not get_key:
                        res[username].pop('key', None)
                    self.pkns_table.close()
                    res.update(peergroups[peergroup])
                    fres[peergroup] = res
                else:
                    res = dict(
                        filter(lambda x: x[1]['username'] == username,
                               self.pkns_table.items())
                    )
                    if not get_key:
                        for x in res:
                            res[x].pop('key', None)
                    self.pkns_table.close()
                    res.update(peergroups[peergroup])
                    fres[peergroup] = res
            return fres

    def get_all_users(self, peergroup: str, fingerprint_only: bool = True):
        '''
        Get all users in the peergroup
        '''
        if peergroup in self.peer_table:
            self.pkns_table = SqliteDict(os.path.join(
                                     os.environ['HOME'],
                                     self.path, 'pkns.db'),
                                     autocommit=True, tablename=peergroup)
            if fingerprint_only:
                return list(self.pkns_table.keys())
            fres = {}
            fres[peergroup] = dict(self.pkns_table)
            fres.update(self.peer_table[peergroup])
            self.pkns_table.close()
            return fres
        else:
            peergroups = self.get_peergroup(peergroup)
            fres = {}
            for peergroup in peergroups:
                self.pkns_table = SqliteDict(os.path.join(
                                    os.environ['HOME'],
                                    self.path, 'pkns.db'),
                                    autocommit=True,
                                    tablename=peergroup)
                fres[peergroup] = dict(self.pkns_table)
                if fingerprint_only:
                    fres[peergroup] = list(self.pkns_table.keys())
                else:
                    fres[peergroup].update(self.peer_table[peergroup])
                self.pkns_table.close()
            return fres

    def rename_user(self, peergroup: str, user: str, new_name: str):
        '''
        User Rename
        '''
        if peergroup not in self.peer_table:
            raise ValueError(
                f'Peergroup {peergroup} not found')
        self.pkns_table = SqliteDict(os.path.join(
                                    os.environ['HOME'],
                                    self.path, 'pkns.db'),
                                    autocommit=True,
                                    tablename=peergroup)
        if user not in self.pkns_table:
            raise ValueError(
                f'User {user} not found')
        user_ = self.pkns_table[user]
        user_['username'] = new_name
        self.pkns_table[user] = user_
        self.pkns_table.close()

    def resolve(self, query: dict) -> dict:
        '''
        PKNS Query Resolver
        '''
        peergroup = query['peergroup']
        username = query['username']
        if peergroup == '':
            rpeers = dict(self.peer_table)
        else:
            rpeers = self.get_peergroup(peergroup)
        if username == '':
            rusers = {}
            for x in rpeers:
                rusers[x] = self.get_all_users(x, fingerprint_only=False)[x]
        else:
            rusers = {}
            for x in rpeers:
                rusers[x] = self.get_user(x, username, True)[x]
        response = dict_merge(rpeers, rusers)
        return response

    def sync(self, sync: dict) -> None:
        '''
        PKNS Table Sync
        '''
        for x in sync:
            if x in self.peer_table:
                data = self.peer_table[x]
                data['name'] = sync[x]['name']
                if type(sync[x]['address']) is set:
                    data['address'].update(sync[x]['address'])
                self.peer_table[x] = data
            else:
                if type(sync[x]['address']) is not set:
                    sync[x]['address'] = set(sync[x]['address'])
                self.peer_table[x] = {}
                self.peer_table[x]['name'] = sync[x]['name']
                self.peer_table[x]['address'] = sync[x]['address']
            sync[x].pop('name', None)
            sync[x].pop('address', None)
            self.sync_users(sync[x], x)

    def sync_users(self, sync: dict, peergroup: str):
        '''
        PKNS User Sync
        '''
        self.pkns_table = SqliteDict(os.path.join(
                                    os.environ['HOME'],
                                    self.path, 'pkns.db'),
                                    autocommit=True,
                                    tablename=peergroup)
        for x in sync:
            if x in self.pkns_table:
                data = self.pkns_table[x]
                if type(sync[x]['address']) is set:
                    data['address'].update(sync[x]['address'])
                self.pkns_table[x] = data
            else:
                if type(sync[x]['address']) is not set:
                    sync[x]['address'] = {sync[x]['address'], }
                self.pkns_table[x] = sync[x]
        self.pkns_table.close()


class PKNS_Server(Base_TCP_Bus):
    """docstring for PKNS_Server"""
    def __init__(self, ip_address='0.0.0.0', port: int = 6300,
                 pkns_path: str = '.pkns'):
        super(PKNS_Server, self).__init__()
        self.pool_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.pool_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ip_address = ip_address
        self.port = port
        self.pkns_path = pkns_path

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
        print(
            f"[{datetime.datetime.now().isoformat(' ')}]" +
            f" {a[0]}@{a[1]}: {pack['tos']}")
        x = PKNS_Response()
        # Query Handler
        if pack['tos'] == 'PKNS:QUERY':
            table = PKNS_Table(self.pkns_path)
            x['reply'] = table.resolve(pack['query'])
        # Ping Handler
        if pack['tos'] == 'PKNS:PING':
            from daemonocle import Daemon
            x['stats'] = Daemon('PKNS Server',
                                pidfile=os.path.join(
                                    os.environ['HOME'],
                                    self.pkns_path, 'PKNS.pid')).get_status()
        # Sync Handler
        if pack['tos'] == 'PKNS:SYNC':
            for i in pack['sync']:
                pack['sync'][i]['address'] = (a[0], )
            try:
                table = PKNS_Table(self.pkns_path)
                table.sync(pack['sync'])
                x['reply'] = table.resolve({'peergroup': '', 'username': ''})
            except Exception as e:
                x['reply'] = 'FAILED'
        # Handler General
        x['status'] = 'WORKING'
        x['server'] = socket.gethostbyaddr(self.socket.getsockname()[0])
        x['client'] = a
        x['protocol'] = PROTOCOLS[c.proto]
        x['transport'] = FAMALIES[c.family]
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
        try:
            self.socket.connect((self.ip_address, self.port))
            self.send(packet)
            response = self.recv()
        except socket.timeout:
            raise ConnectionError(
                'Connection Timeout'
            )
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
            + r'(?P<peergroup>[A-Fa-f0-9]{16}|[^$\/\\\.\,/w]{0,100})?'\
            + r'/?(?P<username>[A-Fa-f0-9]{16}|[^$\/\\\.\,/w]{0,100})?$'
    query = re.match(regex, query_str).groupdict()
    query = {k: v for k, v in query.items()
             if v is not None}
    if query['base'] == '':
        query['base'] = '127.0.0.1:6300'
        query['ipv4'] = '127.0.0.1'
        query['port'] = ':6300'
        query.pop('ipv6', None)
        query.pop('domain', None)
    return query
