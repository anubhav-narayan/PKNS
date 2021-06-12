#!/usr/bin/env python3
'''
PKNS CLI
'''

__version__ = "0.3.6"
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
@cli.command('path', short_help=f'Table Path relative to {os.environ["HOME"]}')
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
@click.argument('name', required=True, type=str)
@click.option('-u', '--username', required=False, type=str,
              help='Your Peergroup Username', default='master',
              show_default=True)
@click.option('-k', '--key-file', required=False, type=click.File('rb'),
              help='Explicit Keys for the Peergroup', default=None)
@click.option('--rsa-size', required=False, type=int,
              help='RSA Key Size', default=3072)
@click.option('-o', '--out-path', type=click.Path(),
              default=os.path.abspath('./'))
@click.pass_obj
def add_peergroup(obj, username: str, name: str, key_file, out_path,
                  rsa_size: int):
    try:
        click.secho(f'Adding Peergroup {name}...', nl=False)
        if key_file is not None:
            key = obj['PKNS'].add_peergroup(name, username, key_file.read(),
                                            get_master=True)
        else:
            key = obj['PKNS'].add_peergroup(name, username, key_file,
                                            rsa_size=rsa_size, get_master=True)
        click.secho('OK', fg='green')
        if key is not None:
            click.secho(
                f'Writing Master Key at {os.path.abspath(out_path)}...',
                nl=False
            )
            with open(
                     os.path.join(out_path, username+'_'+name+'.pem'),
                     'wb'
                 ) as f:
                f.write(key)
            click.secho('OK', fg='green')
    except Exception as fail:
        click.secho('FAILED', fg='red')
        raise click.ClickException(fail)
    pass


@tabman.command('get-peergroup', short_help='Get Info of a Peergroup')
@click.argument('name', required=True, type=str)
@click.pass_obj
def get_peergroup(obj, name: str):
    from pprint import pprint
    try:
        click.secho(f'Finding Peergroup {name}...', nl=False)
        res = obj['PKNS'].get_peergroup(name)
        if res != {}:
            click.secho('FOUND', fg='green')
            pprint(res)
        else:
            click.secho('NOT FOUND', fg='red')
    except Exception as fail:
        click.secho('FAILED', fg='red')
        raise click.ClickException(fail)


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
    except Exception as fail:
        click.secho('FAILED', fg='red')
        raise click.ClickException(fail)
    pass


@tabman.command('del-peergroup', short_help='Delete/Leave a Peergroup')
@click.argument('fingerprint', required=True, type=str)
@click.pass_obj
def del_peergroup(obj, fingerprint: str):
    try:
        click.secho(f'Removing Peergroup {fingerprint}...', nl=False)
        obj['PKNS'].remove_peergroup(fingerprint)
        click.secho('OK', fg='green')
    except Exception:
        click.secho('FAILED', fg='red')
        raise Exception
    pass


@tabman.command('add-user', short_help='Add Users to a Peergroup')
@click.option('-k', '--key', type=click.File('rb'), default=None,
              help='Explicit Key File for User')
@click.argument('username', type=str)
@click.argument('peergroup', type=str)
@click.argument('address', nargs=-1, required=True)
@click.option('-o', '--out-path', type=click.Path(),
              help='Master Key Output Path')
@click.pass_obj
def add_user(obj, peergroup: str, username: str, address,
             key: str = None, out_path: str = '.'):
    '''
    Add USERNAME to a PEERGROUP
    '''
    from hashlib import shake_128
    try:
        click.secho(f'Adding {username} to {peergroup}...')
        if key:
            key_file = key.read()
            fingerprint = shake_128(key_file).hexdigest(8)
        else:
            from Crypto.PublicKey import RSA
            key = RSA.generate(4096)
            key_file = key.public_key().export_key()
            click.secho('Writing Master Key...', nl=False)
            with open(os.path.join(username+'.pem'), 'wb') as f:
                f.write(key.export_key())
            click.secho('OK', fg='green')
            fingerprint = shake_128(key_file).hexdigest(8)
        peergroups = obj['PKNS'].get_peergroup(peergroup)
        if len(peergroups) < 1:
            click.secho(f'Peergroup {peergroup} not found', color='red')
            return
        if len(peergroups) > 1:
            click.secho(f'Multiple Peergroups named {peergroup}')
            for x in peergroups:
                click.secho(f'{x}:{x["name"]}')
            peergroup = click.prompt('Enter Fingerprint',
                                     default=[x for x in peergroups][0])
        else:
            peergroup = [x for x in peergroups][0]
        obj['PKNS'].add_user(key_file, username, address,
                             fingerprint, peergroup)
        click.secho('DONE!', fg='green')
    except Exception as fail:
        click.secho('FAILED', fg='red')
        raise click.ClickException(fail)
    pass


@tabman.command('get-user', short_help='Get Users\' Info from a Peergroup')
@click.argument('name', required=True, type=str)
@click.argument('peergroup', required=True)
@click.pass_obj
def get_user(obj, peergroup: str, name: str):
    from pprint import pprint
    try:
        click.secho(f'Getting {name} from {peergroup}...', nl=False)
        peergroups = obj['PKNS'].get_peergroup(peergroup)
        if len(peergroups) < 1:
            click.secho(f'Peergroup {peergroup} not found', color='red')
            return
        if len(peergroups) > 1:
            click.secho(f'Multiple Peergroups named {peergroup}')
            for x in peergroups:
                click.secho(f'{x}:{x["name"]}')
            peergroup = click.prompt('Enter Fingerprint',
                                     default=[x for x in peergroups][0])
        else:
            peergroup = [x for x in peergroups][0]
        res = obj['PKNS'].get_user(peergroup, name)
        ires = dict(
            filter(
                lambda x: type(x[1]) is dict,
                res[peergroup].items()
            )
        )
        if ires != {}:
            click.secho('FOUND', fg='green')
            pprint(res)
        else:
            click.secho('NOT FOUND', fg='red')
    except Exception:
        click.secho('FAILED', fg='red')
        raise Exception


@tabman.command('rename-user', short_help='Rename a User from a Peergroup')
@click.argument('fingerprint', required=True)
@click.option('-p', '--peergroup', required=True, help='Peergroup Fingerprint')
@click.option('-r', '--rename', required=True, help='New Username')
@click.pass_obj
def rename_user(obj, fingerprint: str, peergroup: str, rename: str):
    try:
        click.secho(f'Renaming {fingerprint} {rename} from {peergroup}...',
                    nl=False)
        peergroups = obj['PKNS'].get_peergroup(peergroup)
        if len(peergroups) < 1:
            click.secho(f'Peergroup {peergroup} not found', color='red')
            return
        if len(peergroups) > 1:
            click.secho(f'Multiple Peergroups named {peergroup}')
            for x in peergroups:
                click.secho(f'{x}:{x["name"]}')
            peergroup = click.prompt('Enter Fingerprint',
                                     default=[x for x in peergroups][0])
        else:
            peergroup = [x for x in peergroups][0]
        obj['PKNS'].rename_user(peergroup, fingerprint, rename)
        click.secho('OK', fg='green')
    except Exception:
        click.secho('FAILED', fg='red')
        raise Exception
    pass


@tabman.command('del-user', short_help='Remove Users from a Peergroup')
@click.argument('fingerprint', required=True)
@click.argument('peergroup', required=True)
@click.pass_obj
def del_user(obj, peergroup: str, fingerprint: str):
    '''
    Delete FINGERPRINT from PEERGROUP
    '''
    try:
        click.secho(f'Removing {fingerprint} from {peergroup}...', nl=False)
        peergroups = obj['PKNS'].get_peergroup(peergroup)
        if len(peergroups) < 1:
            click.secho(f'Peergroup {peergroup} not found', color='red')
            return
        if len(peergroups) > 1:
            click.secho(f'Multiple Peergroups named {peergroup}')
            for x in peergroups:
                click.secho(f'{x}:{x["name"]}')
            peergroup = click.prompt('Enter Fingerprint',
                                     default=[x for x in peergroups][0])
        else:
            peergroup = [x for x in peergroups][0]
        obj['PKNS'].purge_user(fingerprint, peergroup)
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
    ctx.obj['WORKER'] = PKNS_Server(ip_address=host, port=port)


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
    click.secho(f'Searching for {query}...', nl=False)
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
        port = int(query.pop('port').strip(':'))
    else:
        port = 6300
    query.pop('base')
    try:
        request = PKNS_Request(host, port)
        packet = PKNS_Query()
        packet['query'] = query
        click.secho('OK', fg='green')
        pprint(request.get(packet))
    except Exception as e:
        click.secho('FAILED', fg='red')
        raise click.ClickException(e)


# Sync
@cli.command('sync', short_help='Remote Server Synchronisation',
             help='PKNS Sync')
@click.argument('address', default='0.0.0.0')
@click.pass_obj
def sync(obj, address: str):
    from pprint import pprint
    request = PKNS_Request(address)
    packet = PKNS_Sync()
    try:
        click.secho(f'Syncing to {address}')
        packet['sync'] = obj['PKNS'].resolve({'peergroup': '',
                                              'username': ''})
        sync = request.get(packet)
        if sync['reply'] != 'FAILED':
            obj['PKNS'].sync(sync['reply'])
            pprint(sync)
        else:
            pprint(sync)
            raise ValueError('Failed')
        click.secho(f'Synced to {address}', fg='green')
    except Exception as e:
        click.secho('FAILED', fg='red')
        raise click.ClickException(e)


def main():
    cli(obj={})


if __name__ == '__main__':
    cli(obj={})
