# Public Key Name System Framework
[![Made with Python3](https://img.shields.io/badge/Made%20With-Python3-blue)](https://www.python.org/) [![GitHub license](https://img.shields.io/badge/license-AGPLv3-purple.svg)](https://github.com/anubhav-narayan/PKNS/blob/master/LICENSE) [![Github version](https://img.shields.io/badge/version-0.4.0-green)
](http://github.com/anubhav-narayan/PKNS) [![Github version](https://img.shields.io/badge/status-Public%20Beta-green)
](http://github.com/anubhav-narayan/PKNS)
This is the Public Key Name System Framework designed as a Public Key Exchange for both centralised and peer-to-peer services. It comes pre-built with useful and powerful CLI tools.
## Installation
### From source
To install from source use the following command, make sure you have `setuptools>=50.0.0`
```bash
python3 seutp.py install
```
We'll get to PyPI soon
## Using the `PKNS_Table` API
The `PKNS_Table` API is the core for the PKNS Local Services found in the `pknscore`
```python
from pkns.pknscore import PKNS_Table
new_table = PKNS_Table(PATH_TO_A_TABLE)
```
 `PATH_TO_A_TABLE` can be a path to an existing table directory or a new table directory.
 The API provides all basic table operations.
## CLI Tools
###  Local Table Manager `tabman`
Managing Local Tables is an essential part of PKNS.
Calling `tabman`
#### Commands
```bash
$ pkns_cli tabman
Usage: pkns_cli tabman [OPTIONS] COMMAND [ARGS]...

  PKNS Table Manager

Options:
  --help  Show this message and exit.

Commands:
  add-peergroup     Add/Create a Peergroup
  add-user          Add Users to a Peergroup
  del-peergroup     Delete/Leave a Peergroup
  del-user          Remove Users from a Peergroup
  get-peergroup     Get Info of a Peergroup
  get-user          Get Users' Info from a Peergroup
  rename-peergroup  Rename a Peergroup
  rename-user       Rename a User from a Peergroup

```
### Server Manager `server`
Server utilities
```bash
$ pkns_cli server
Usage: pkns_cli server [OPTIONS] COMMAND [ARGS]...

  PKNS Server Manager

Options:
  -i, --host TEXT     IP Address to bind  [default: 0.0.0.0]
  -p, --port INTEGER  Port to bind  [default: 6300]
  --help              Show this message and exit.

Commands:
  restart  Restart PKNS Server
  start    Start the PKNS Server
  status   PKNS Server Status
  stop     Stop the PKNS Server

```
### Other utilities
#### Ping
```bash
$ pkns_cli ping --help
Usage: pkns_cli ping [OPTIONS] [ADDRESS]

  PKNS Ping

Options:
  -n, --nop INTEGER  Number of Pings to send
  --help             Show this message and exit.

```
#### Sync
```bash
$ pkns_cli sync --help
Usage: pkns_cli sync [OPTIONS] [ADDRESS]

  PKNS Sync

Options:
  --help  Show this message and exit.
```
