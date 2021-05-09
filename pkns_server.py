#!/usr/bin/env python3
'''
PKNS CLI
'''

__version__ = "0.3.0-Windows"
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
from pkns.Service import Service_Base, win32serviceutil
import click
import datetime
import os

# Path
PATH = '.pkns'


# CLI Starts Here
# @click.group(help=f'PKNS CLI {__version__}')
# @click.pass_obj
# def cli(obj):
#     obj['PKNS'] = PKNS_Table(PATH)
#     pass


# # Path
# @cli.command('path', short_help='Table Path relative to HOME')
# @click.argument('path', type=click.Path(), default='.pkns')
# def path(path: str):
#     global PATH
#     if not os.path.exists(os.path.join(os.environ['HOME'], path)):
#         os.mkdir(os.path.join(os.environ['HOME'], path))
#     PATH = path


# # Server Manager
# @cli.group('server', short_help='PKNS Server Management',
#            help='PKNS Server Manager')
# @click.option('-i', '--host', help='IP Address to bind', default='0.0.0.0',
#               show_default=True)
# @click.option('-p', '--port', help='Port to bind', default=6300, type=int,
#               show_default=True)
# @click.pass_context
# def server(ctx, host: str, port: int):
#     # ctx.obj['WORKER'] = PKNS_Server()
#     server = PKNS_Server(host, port)
#     service = Service_Base('PKNS Server', server.serve_endless, 'PKNS Server')
#     ctx.obj['SERV'] = service


# @server.command('run')
# @click.pass_context
# def run(ctx):
#     win32serviceutil.HandleCommandLine(ctx.obj['SERV'])

if __name__ == '__main__':
    # cli(obj={})
    server = PKNS_Server('localhost', 6300)
    service = Service_Base('PKNS Server', server.serve_endless, 'PKNS Server')
    service.cmd_line_parser()