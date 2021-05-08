#!/usr/bin/env python3
'''
PKNS CLI
'''

__version__ = "0.3.0"
__author__ = "Anubhav Mattoo"
__email__ = "anubhavmattoo@outlook.com"
__license__ = "AGPLv3"
__status__ = "Public Beta"


from pkns.pknscore import (
    PKNS_Table,
    PKNS_Server,
    PKNS_Request,
    PKNS_Ping,
    PKNS_Query,
    PKNS_Sync,
    parse
)
from daemonocle import Daemon
import click
import datetime
import os

# Path
PATH = '.pkns'


# CLI Starts Here
@click.group(help=f'PKNS CLI {__version__}')
@click.pass_obj
def cli(obj):
    obj['PKNS'] = PKNS_Table(PATH)
    pass


# Path
@cli.command('path', short_help='Table Path relative to HOME')
@click.argument('path', type=click.Path(), default='.pkns')
def path(path: str):
    global PATH
    if not os.path.exists(os.path.join(os.environ['HOME'], path)):
        os.mkdir(os.path.join(os.environ['HOME'], path))
    PATH = path


# Table Manager
@cli.group(short_help='PKNS Table Management', help='PKNS Table Manager')
@click.pass_obj
def tabman(obj):
    pass


@tabman.command('add-peergroup', short_help='Add/Create a Peergroup')
@click.option('-n', '--name', required=True, type=str,
              help='Name of the Peergroup')
@click.option('-u', '--username', required=False, type=str,
              help='Your Peergroup Username', default='master',
              show_default=True)
@click.option('-k', '--key-file', required=False, type=click.Path(),
              help='Explicit Keys for the Peergroup', default=None)
@click.pass_obj
def add_peergroup(obj, username, name, key_file):
    try:
        click.secho(f'Adding Peergroup {name}...', nl=False)
        obj['PKNS'].add_peergroup(name, username, key_file)
        click.secho('OK', fg='green')
    except Exception as fail:
        click.secho('FAILED', fg='red')
        raise fail
    pass


@tabman.command('get-peergroup', short_help='Get Info of a Peergroup')
@click.argument('name', required=True, type=str)
@click.pass_obj
def get_peergroup(obj, name: str):
    from pprint import pprint
    try:
        click.secho(f'Finding Peergroup {name}...', nl=False)
        res = obj['PKNS'].get_peergroup(name)
        click.secho('FOUND', fg='green')
    except Exception as fail:
        click.secho('FAILED', fg='red')
        raise fail
    pprint(res)


@tabman.command('rename-peergroup', short_help='Rename a Peergroup')
@click.option('-n', '--name', required=True, type=str,
              help='Fingerprint of the Peergroup')
@click.option('-r', '--rename', required=True, type=str,
              help='New Name of the Peergroup')
@click.pass_obj
def rename_peergroup(obj, name: str, rename: str):
    try:
        click.secho(f'Renaming Peergroup {name} to {rename}...', nl=False)
        obj['PKNS'].rename_peergroup(name, rename)
        click.secho('OK', fg='green')
    except Exception:
        click.secho('FAILED', fg='red')
        raise Exception
    pass


@tabman.command('del-peergroup', short_help='Delete/Leave a Peergroup')
@click.option('-n', '--name', required=True, type=str,
              help='Fingerprint of the Peergroup')
@click.pass_obj
def del_peergroup(obj, name: str):
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
        obj['PKNS'].get_peergroup(peergroup)
        obj['PKNS'].add_user(key_file, username, list(address))
        click.secho('OK', fg='green')
    except Exception:
        click.secho('FAILED', fg='red')
        raise Exception
    pass


@tabman.command('get-user', short_help='Get Users\' Info from a Peergroup')
@click.argument('name', required=True, type=str)
@click.argument('peergroup', required=True)
@click.pass_obj
def get_user(obj, peergroup: str, name: str):
    from pprint import pprint
    try:
        click.secho(f'Getting {name} from {peergroup}...', nl=False)
        res = obj['PKNS'].get_user(peergroup, name)
        click.secho('FOUND', fg='green')
    except Exception:
        click.secho('FAILED', fg='red')
        raise Exception
    pprint(res)


@tabman.command('rename-user', short_help='Rename a User from a Peergroup')
@click.argument('fingerprint', required=True)
@click.option('-p', '--peergroup', required=True, help='Peergroup Fingerprint')
@click.option('-r', '--rename', required=True, help='New Username')
@click.pass_obj
def rename_user(obj, fingerprint: str, peergroup: str, rename: str):
    try:
        click.secho(f'Renaming {fingerprint} {rename} from {peergroup}...',
                    nl=False)
        obj['PKNS'].rename_user(peergroup, fingerprint, rename)
        click.secho('OK', fg='green')
    except Exception:
        click.secho('FAILED', fg='red')
        raise Exception
    pass


@tabman.command('del-user', short_help='Remove Users from a Peergroup')
@click.argument('fingerprint', required=True)
@click.option('-p', '--peergroup', required=True, help='Peergroup Fingerprint')
@click.pass_obj
def del_user(obj, peergroup: str, username: str):
    try:
        click.secho(f'Removing {username} from {peergroup}...', nl=False)
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
@click.pass_context
def server(ctx, host: str, port: int):
    ctx.obj['WORKER'] = PKNS_Server()


@server.command('start', short_help='Start the PKNS Server')
@click.option('--debug', type=bool, default=False, is_flag=True,
              help='Enable Debug Info')
@click.pass_context
def start(ctx, debug):
    click.secho('PKNS Server Address: ', nl=False)
    click.secho(
        f"{ctx.obj['WORKER'].ip_address}:{ctx.obj['WORKER'].port}",
        fg='green'
    )
    daemon = Daemon('PKNS Server', worker=ctx.obj['WORKER'].serve_endless,
                    detach=(not debug), pidfile=os.path.abspath(
                        os.environ['HOME']+"/.pkns/PKNS.pid"),
                    work_dir=os.path.abspath(os.environ['HOME']),
                    stdout_file=os.path.abspath(
                        os.environ['HOME'] + "/.pkns/PKNS.log"),
                    stderr_file=os.path.abspath(
                        os.environ['HOME'] + "/.pkns/PKNS_error.log"),
                    uid=os.getuid(), gid=os.getgid())
    daemon.do_action('start')


@server.command('stop', short_help='Stop the PKNS Server')
@click.option('-f', '--force', help='Force Stop', is_flag=True, default=False)
def stop(force):
    daemon = Daemon('PKNS Server', pidfile=os.path.abspath(
                        os.environ['HOME']+"/.pkns/PKNS.pid"))
    daemon.stop(force=force)


@server.command('status', short_help='PKNS Server Status')
@click.option('-j', '--json', help='Return JSON', default=False, is_flag=True)
def status(json):
    daemon = Daemon('PKNS Server', pidfile=os.path.abspath(
                        os.environ['HOME']+"/.pkns/PKNS.pid"))
    daemon.status(json=json)


@server.command('restart', short_help='Restart PKNS Server')
@click.option('-f', '--force', help='Force Stop', is_flag=True, default=False)
@click.option('--debug', type=bool, default=False, is_flag=True,
              help='Enable Debug Info')
@click.pass_context
def restart(ctx, debug, force):
    ctx.invoke(stop, force=force)
    ctx.invoke(start, debug=debug)


# Ping
@cli.command('ping', short_help='PKNS Server Ping', help='PKNS Ping')
@click.argument('address', default='0.0.0.0')
@click.option('-n', '--nop', help='Number of Pings to send', type=int,
              default=1)
def ping(address, nop: int):
    from pprint import pprint
    request = PKNS_Request(address)
    packet = PKNS_Ping()
    time = []
    for x in range(nop):
        start = datetime.datetime.now()
        pprint(request.get(packet))
        rtime = (datetime.datetime.now() - start)
        time.append(rtime.microseconds / 1E3)
        print(f'time={rtime.microseconds / 1E3}ms')
    print(f'Average Time={sum(time)/len(time):.3f}ms, Packet(s)={nop}')


# Query
@cli.command('query', short_help='PKNS Query', help='PKNS Query')
@click.argument('query', type=str)
@click.pass_obj
def query(obj, query: str):
    from pprint import pprint
    query = parse(query)
    if 'domain' in query:
        host = query.pop('domain').split(':')[0]
    if 'dport' in query:
        port = int(query.pop('dport').strip(':'))
    else:
        port = 6300
    if 'ipv4' in query:
        host = query.pop('ipv4')
    if 'port' in query:
        port = int(query.pop('port'))
    else:
        port = 6300
    query.pop('base')
    request = PKNS_Request(host, port)
    packet = PKNS_Query()
    packet['query'] = query
    pprint(request.get(packet))


# Sync
@cli.command('sync', short_help='Remote Server Synchronisation',
             help='PKNS Sync')
@click.argument('address', default='0.0.0.0')
@click.pass_obj
def query(obj, address: str):
    from pprint import pprint
    request = PKNS_Request(address)
    packet = PKNS_Sync()
    try:
        click.secho(f'Syncing to {address}')
        packet['sync'] = obj['PKNS'].resolve({'peergroup': '',
                                              'username': ''})
        sync = request.get(packet)
        obj['PKNS'].sync(sync['reply'])
        pprint(sync)
        click.secho(f'Synced to {address}', fg='green')
    except Exception as e:
        raise
        click.secho('FAILED', fg='red')


def main():
    cli(obj={})


if __name__ == '__main__':
    cli(obj={})