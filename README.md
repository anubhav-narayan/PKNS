
# Public Key Name System Framework
[![Made with Python3](https://img.shields.io/badge/Made%20With-Python3-blue)](https://www.python.org/) [![GitHub license](https://img.shields.io/badge/license-AGPLv3-purple.svg)](https://github.com/anubhav-narayan/PKNS/blob/master/LICENSE) [![Github version](https://img.shields.io/badge/version-0.4.0-green)
](http://github.com/anubhav-narayan/PKNS) [![Github version](https://img.shields.io/badge/status-Public%20Beta-green)
](http://github.com/anubhav-narayan/PKNS)\
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
new_table = PKNS_Table(PATH_TO_A_TABLE_DIR)
```
 `PATH_TO_A_TABLE` can be a path to an existing table directory or a new table directory, defaults to `~/.pkns`.
 The API provides all basic table operations.
 ## Using the `PKNS_Server` API
 The `PKNS_Server` API is the core of PKNS Network Services found in the  `pknscore`. It provides the correct server handling and configuration for a hosted PKNS Services. The PKNS service runs on the default port `6300` .  It is capable to handle multiple clients and process multiple requests and can be safely daemonized.
 ```python
 from pkns.pknscore import PKNS_Server
 server = PKNS_Server(IP_ADDR, PORT, PATH_TO_A_TABLE_DIR)
 ```
 `IP_ADDR` is the IP Address to use for the server, defaults to `0.0.0.0`,  `PORT` is the port to be used for the server, defaults to `6300`,  `PATH_TO_A_TABLE` can be a path to an existing table directory or a new table directory, defaults to `~/.pkns`.
## Query Syntax
PKNS Query is used for better integration of centralised servers. The query follows a fixed Syntax
```
pkns://HOST_SERVER[:PORT][/PEERGROUP][/USER]
```
## CLI Tools
CLI Tools help manage the PKNS Tables and Servers easily, they also include useful functions.
###  Local Table Manager `tabman`
Managing Local Tables
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
  get-user          Get Users\' Info from a Peergroup
  rename-peergroup  Rename a Peergroup
  rename-user       Rename a User from a Peergroup

```
### Server Manager `server`
Server Utilities
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
Ping a Local or Remote Server
```bash
$ pkns_cli ping --help
Usage: pkns_cli ping [OPTIONS] [ADDRESS]

  PKNS Ping

Options:
  -n, --nop INTEGER  Number of Pings to send
  --help             Show this message and exit.

```
#### Query
Query Local or Remote Server
```bash
$ pkns_cli query --help
Usage: pkns_cli query [OPTIONS] QUERY

  PKNS Query

Options:
  --help  Show this message and exit.
``` 
#### Sync
Sync to Local or Remote Server
```bash
$ pkns_cli sync --help
Usage: pkns_cli sync [OPTIONS] [ADDRESS]

  PKNS Sync

Options:
  --help  Show this message and exit.
```
