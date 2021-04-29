#!/usr/bin/env python3
'''
PKNS Class
'''

__version__ = "0.5.15"
__author__ = "Anubhav Mattoo"

from sqlitedict import SqliteDict
import os
from Crypto.PublicKey import RSA
import click
import socket
import threading
from loopyCryptor import Cryptor, Serializer
from daemonocle import Daemon
import datetime
from hashlib import shake_128


class PKNS_Table():
    """
    Public Key Name System
    """
    def __init__(self):
        self.peer_table = SqliteDict(os.path.abspath('./pkns.db'),
                                     autocommit=True, tablename='peergroups')
        self.peer_group = 'DEFAULT'
        pass

    def add_user(self,
                 key: str, username: dict,
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
        if key_file is not None:
            key_file = open(key_file, 'rb').read()
        else:
            key = RSA.generate(4096)
            key_public = key.publickey()
            key_file = key_public.export_key()
            master = key.export_key()
            with open(os.path.abspath(f'./master/PKNS_{peergroup}_MASTER.pem'),
                      'wb') as f:
                f.write(master)
        self.peer_table[peergroup] = shake_128(master).hexdigest(8)
        self.peer_group = peergroup
        self.add_user(key_file, username,
                      '0.0.0.0', shake_128(master).hexdigest(8))

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
        self._verify_ack = lambda ack, size, md5:\
                                  Cryptor.md5((size, md5)).encode() == ack

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
    def __init__(self, ip_address = '0.0.0.0', port: int = 6300):
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
        x = self.recv()
        print(f"[{datetime.datetime.now().isoformat(' ')}] {a[0]}@{a[1]}: {x}")
        # query handler
        x = PKNS_Response()

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


class PKNS_Request(Base_TCP_Bus):
    """docstring for PKNS_Request"""
    def __init__(self, ip_address = '127.0.0.1', port: int = 6300):
        super(PKNS_Request, self).__init__()
        self.ip_address = ip_address
        self.port = port

    def get(self, packet: PKNS_Packet_Base):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.settimeout(5)
        self.socket.connect((self.ip_address, self.port))
        packet['host'] = self.ip_address
        packet['port'] = self.port
        self.send(packet)
        response = self.recv()
        self.socket.close()
        return response


# CLI Starts Here
@click.group(help=f'PKNS CLI {__version__}')
@click.pass_obj
def cli(obj):
    obj['PKNS'] = PKNS_Table()
    pass


# Table Manager
@cli.group(short_help='PKNS Table Management', help='PKNS Table Manager')
@click.pass_obj
def tabman(obj):
    pass


@tabman.command('add-peergroup', short_help='Add/Create a Peergroup')
@click.option('-n', '--name', required=True, type=str, help='Name of the Peergroup')
@click.option('-u', '--username', required=False, type=str, help='Your Peergroup Username', default='master', show_default=True)
@click.option('-k', '--key-file', required=False, type=click.Path(), help='Explicit Keys for the Peergroup', default=None)
@click.pass_obj
def add_peergroup(obj, username, name, key_file):
    try:
        click.secho(f'Adding Peergroup {name}...', nl=False)
        obj['PKNS'].add_peergroup(name, username, key_file)
        click.secho('OK', fg='green')
    except Exception:
        click.secho('FAILED', fg='red')
        raise Exception
    pass


@tabman.command('del-peergroup', short_help='Delete/Leave a Peergroup')
@click.option('-n', '--name', required=True, type=str,
              help='Name of the Peergroup')
@click.pass_obj
def del_peergroup(obj, name):
    try:
        click.secho(f'Removing Peergroup {name}...', nl=False)
        obj['PKNS'].remove_peergroup(name)
        click.secho('OK', fg='green')
    except Exception:
        click.secho('FAILED', fg='red')
        raise Exception
    pass


@tabman.command('add-user', short_help='Add Users to a Peergroup')
@click.argument('peergroup', default='DEFAULT')
@click.option('-k', '--key', type=click.Path())
@click.argument('fingerprint', type=str, required=True)
@click.argument('username')
@click.argument('address', nargs=-1, required=True)
@click.pass_obj
def add_user(obj, fingerprint: str, peergroup: str, key: os.PathLike,
             username: str, address):
    try:
        click.secho(f'Adding {username} to {peergroup}...', nl=False)
        key_file = open(key).read()
        obj['PKNS'].add_user(key_file, username, list(address))
        click.secho('OK', fg='green')
    except Exception:
        click.secho('FAILED', fg='red')
        raise Exception
    pass


@tabman.command('del-user', short_help='Remove Users from a Peergroup')
@click.argument('peergroup', default='DEFAULT')
@click.argument('fingerprint', required=True)
@click.pass_obj
def del_user(obj, peergroup: str, username: str):
    try:
        click.secho(f'Removing {username} to {peergroup}...', nl=False)
        obj['PKNS'].purge_user(fingerprint)
        click.secho('OK', fg='green')
    except Exception:
        click.secho('FAILED', fg='red')
        raise Exception
    pass


# Server Manager
@cli.group('server', short_help='PKNS Server Management',
           help='PKNS Server Manager')
@click.option('-i', '--host', help='IP Address to bind', default='0.0.0.0',
              show_default=True)
@click.option('-p', '--port', help='Port to bind', default=6300, type=int,
              show_default=True)
@click.pass_obj
def server(obj, host: str, port: int):
    obj['WORKER'] = PKNS_Server()


@server.command('start', short_help='Start the PKNS Server')
@click.option('--debug', type=bool, default=False, is_flag=True,
              help='Enable Debug Info')
@click.pass_obj
def start(obj, debug):
    click.secho('PKNS Server Address: ', nl=False)
    click.secho(f"{obj['WORKER'].ip_address}", fg='green')
    daemon = Daemon('PKNS Server', worker=obj['WORKER'].serve_endless,
                    detach=(not debug), pidfile="./PKNS.pid",
                    work_dir='./',
                    stdout_file="./PKNS.log", stderr_file="./PKNS_error.log",
                    uid=os.getuid(), gid=os.getgid())
    daemon.do_action('start')


@server.command('stop', short_help='Stop the PKNS Server')
@click.option('-f', '--force', help='Force Stop', is_flag=True, default=False)
@click.pass_obj
def stop(obj, force):
    daemon = Daemon('PKNS Server', pidfile="./PKNS.pid")
    daemon.stop(force=force)


@server.command('status', short_help='File Server Status')
@click.option('-j', '--json', help='Return JSON', default=False, is_flag=True)
@click.pass_obj
def status(obj, json):
    daemon = Daemon('PKNS Server', pidfile="./PKNS.pid")
    daemon.status(json=json)


@server.command('reload', short_help='Reload Daemon')
@click.pass_obj
def reload(obj):
    daemon = Daemon('PKNS Server', pidfile="./PKNS.pid")
    daemon.reload()


@server.command('restart', short_help='Restart PKNS Server')
@click.option('-f', '--force', help='Force Stop', is_flag=True, default=False)
@click.option('--debug', type=bool, default=False, is_flag=True,
              help='Enable Debug Info')
@click.pass_obj
def reload(obj, debug, force):
    daemon = Daemon('PKNS Server', pidfile="./PKNS.pid")
    daemon.restart(force=force, debug=debug)


# Ping
@cli.command('ping')
@click.argument('address', default='0.0.0.0')
@click.option('-n', '--nop', help='Number of Pings to send', type=int,
              default=1)
def ping(address, nop: int):
    request = PKNS_Request(address)
    packet = PKNS_Ping()
    for x in range(nop):
        start = datetime.datetime.now()
        print(request.get(packet))
        print((datetime.datetime.now() - start))


if __name__ == '__main__':
    cli(obj={})
