#!/usr/bin/env python3
'''
PKNS CLI
'''

__version__ = "0.1.4-Windows"
__author__ = "Anubhav Mattoo, Om Belote"


from pknscore import (
    PKNS_Table,
    PKNS_Server,
    PKNS_Request,
    PKNS_Ping,
    PKNS_Query,
    PKNS_Sync,
    parse
    )
# from daemonocle import Daemon
import click
import datetime
import os


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
@click.argument('peergroup', default='DEFAULT')
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


@tabman.command('del-user', short_help='Remove Users from a Peergroup')
@click.argument('fingerprint', required=True)
@click.argument('peergroup', default='DEFAULT')
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
@click.pass_context
def server(ctx, host: str, port: int):
    ctx.obj['WORKER'] = PKNS_Server()


@server.command('start', short_help='Start the PKNS Server')
@click.option('--debug', type=bool, default=False, is_flag=True,
              help='Enable Debug Info')
@click.pass_context
def start(ctx, debug):
    click.secho('PKNS Server Address: ', nl=False)
    click.secho(f"{ctx.obj['WORKER'].ip_address}", fg='green')
    ctx.obj['WORKER'].serve_endless()
    # daemon = Daemon('PKNS Server', worker=ctx.obj['WORKER'].serve_endless,
    #                 detach=(not debug), pidfile="./PKNS.pid",
    #                 work_dir='./',
    #                 stdout_file="./PKNS.log", stderr_file="./PKNS_error.log",
    #                 uid=os.getuid(), gid=os.getgid())
    # daemon.do_action('start')


# @server.command('stop', short_help='Stop the PKNS Server')
# @click.option('-f', '--force', help='Force Stop', is_flag=True, default=False)
# def stop(force):
    # daemon = Daemon('PKNS Server', pidfile="./PKNS.pid")
    # daemon.stop(force=force)


# @server.command('status', short_help='PKNS Server Status')
# @click.option('-j', '--json', help='Return JSON', default=False, is_flag=True)
# def status(json):
#     daemon = Daemon('PKNS Server', pidfile="./PKNS.pid")
#     daemon.status(json=json)


# @server.command('restart', short_help='Restart PKNS Server')
# @click.option('-f', '--force', help='Force Stop', is_flag=True, default=False)
# @click.option('--debug', type=bool, default=False, is_flag=True,
#               help='Enable Debug Info')
# @click.pass_context
# def restart(ctx, debug, force):
#     ctx.invoke(stop, force=force)
#     ctx.invoke(start, debug=debug)


# Ping
@cli.command('ping')
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
@cli.command('query')
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
@cli.command('sync')
@click.argument('address', default='0.0.0.0')
@click.pass_obj
def query(obj, address: str):
    from pprint import pprint
    request = PKNS_Request(address)
    packet = PKNS_Sync()
    packet['sync'] = obj['PKNS'].resolve({'peergroup': '',
                                          'username': ''})
    pprint(request.get(packet))


if __name__ == '__main__':
    cli(obj={})
