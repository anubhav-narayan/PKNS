"""
PKNS Table - Local Table Management
"""

import os
from db86 import Database
from Crypto.PublicKey import RSA
from hashlib import shake_128
from concurrent.futures import ThreadPoolExecutor

from .utils import dict_merge


class PKNSTable:
    """
    Public Key Name System local table for managing peergroups and users.
    
    This class handles the storage and management of PKNS data using db86 Database.
    It maintains peergroups (groups of users) and their associated users with keys and addresses.
    Key processes include adding/removing peergroups and users, querying data, and synchronization.
    """

    def __init__(self, path: str = '.pkns'):
        """
        Initialize the PKNS Table instance.
        
        Creates the database directory if it doesn't exist, initializes the db86 Database
        with autocommit enabled for automatic persistence, and sets up the peer_table
        storage for managing peergroups and vault for master keys.
        
        NOTE: The vault table is LOCAL-ONLY and NEVER exposed over the network.
        """
        self.path = path
        home_path = os.path.join(os.environ['HOME'], self.path)
        if not os.path.exists(home_path):
            os.mkdir(home_path)
        self.db = Database(os.path.join(home_path, 'pkns.db'), autocommit=True)
        self.peer_table = self.db['peergroups']
        self.vault = self.db['vault']
        self._protected_tables = {'vault', 'peergroups'}

    def add_user(self, key: bytes, username: str, address: tuple,
                 fingerprint: str, peergroup: str) -> None:
        """
        Add or update a user entry in the table.
        
        Process:
        1. Access the peergroup's user storage.
        2. Check if the fingerprint exists with a different username (invalid).
        3. If fingerprint exists with same username, update address instead.
        4. Otherwise, create new user entry with username, address set, and key.
        """
        self.pkns_table = self.db[peergroup]
        if fingerprint in self.pkns_table and \
           username != self.pkns_table[fingerprint]['username']:
            raise ValueError("Invalid Fingerprint")
        if fingerprint in self.pkns_table and \
           username == self.pkns_table[fingerprint]['username']:
            self.add_address(fingerprint, address, peergroup)
            return
        self.pkns_table[fingerprint] = {
            'username': username,
            'address': address if isinstance(address, list) else list(set(address)),
            'key': key.decode()
        }

    def add_address(self, fingerprint: str, address: tuple,
                    peergroup: str) -> None:
        """
        Add or update addresses for a user in the table.
        
        Process:
        1. Access the peergroup's user storage.
        2. Update the user's address set with the new address(es).
        """
        self.pkns_table = self.db[peergroup]
        if isinstance(address, list):
            self.pkns_table[fingerprint]['address'].extend(address)
        else:
            self.pkns_table[fingerprint]['address'].extend(list(set(address)))

    def remove_address(self, fingerprint: str, address: tuple,
                       peergroup: str) -> None:
        """
        Remove an address from a user's address set.
        
        Process:
        1. Access the peergroup's user storage.
        2. Remove the specified address from the user's address set.
        """
        self.pkns_table = self.db[peergroup]
        self.pkns_table[fingerprint]['address'].remove(address)

    def purge_user(self, fingerprint: str, peergroup: str) -> None:
        """
        Remove a user from the table.
        
        Process:
        1. Validate that the peergroup exists.
        2. Access the peergroup's user storage.
        3. Validate that the user exists.
        4. Remove the user entry.
        """
        if peergroup not in self.peer_table:
            raise ValueError("Invalid Peergroup")
        self.pkns_table = self.db[peergroup]
        if fingerprint not in self.pkns_table:
            raise ValueError("Invalid Key")
        self.pkns_table.pop(fingerprint)

    def add_peergroup(self, peergroup: str, username: str, key_file=None,
                      rsa_size: int = 3072,
                      get_master: bool = False):
        """
        Add a new peergroup.
        
        Process:
        1. Check if peergroup already exists.
        2. If no key_file provided, generate RSA key pair and store master key in vault.
        3. Compute fingerprint from peergroup name and public key.
        4. Add peergroup entry to peer_table with name and default address.
        5. Add the master user to the peergroup.
        6. Optionally return the master key if requested.
        """
        if peergroup in self.peer_table:
            raise NameError(f'{peergroup} already exists!')
        
        if key_file is None:
            key = RSA.generate(rsa_size)
            key_public = key.publickey()
            key_file = key_public.export_key()
            master = key.export_key()
            fingerprint = shake_128(peergroup.encode('utf8') + key_file).hexdigest(8)
            
            # Store master key in vault
            self.vault[fingerprint] = {
                'peergroup': peergroup,
                'master_key': master.decode('utf8') if isinstance(master, bytes) else master
            }
        else:
            fingerprint = shake_128(peergroup.encode('utf8') + key_file).hexdigest(8)
        
        self.peer_table[fingerprint] = {
            'name': peergroup,
            'address': ['0.0.0.0']
        }
        self.add_user(key_file, username, '0.0.0.0',
                      shake_128(key_file).hexdigest(8), fingerprint)
        
        if get_master:
            try:
                return key.export_key()
            except Exception:
                return None

    def remove_peergroup(self, peergroup: str):
        """
        Remove a peergroup and all its users.
        
        Process:
        1. Remove the peergroup from peer_table.
        2. Clear all users in the peergroup's storage.
        3. Remove the peergroup's master key from vault if it exists.
        """
        try:
            # Find and remove master key from vault
            for fingerprint, vault_data in self.vault.items():
                if vault_data.get('peergroup') == peergroup:
                    self.vault.pop(fingerprint)
                    break
            
            self.peer_table.pop(peergroup)
            self.db[peergroup].clear()
        except KeyError:
            raise Exception(f'Peergroup {peergroup} does not exist')

    def get_master_key(self, fingerprint: str):
        """
        Retrieve a master key from the vault (LOCAL-ONLY).
        
        This method is for local in-process access only and should NEVER be exposed
        over the network. Master keys are cryptographic secrets that must remain private.
        
        Process:
        1. Check if fingerprint exists in vault.
        2. Return the master key if found, otherwise raise KeyError.
        """
        if fingerprint not in self.vault:
            raise KeyError(f"Master key for {fingerprint} not found in vault")
        vault_entry = self.vault[fingerprint]
        master_key = vault_entry.get('master_key')
        if isinstance(master_key, str):
            return master_key.encode('utf8')
        return master_key

    def remove_master_key(self, fingerprint: str) -> None:
        """
        Remove a master key from the vault.
        
        Process:
        1. Check if fingerprint exists in vault.
        2. Remove the entry if found, otherwise raise KeyError.
        """
        if fingerprint not in self.vault:
            raise KeyError(f"Master key for {fingerprint} not found in vault")
        self.vault.pop(fingerprint)

    def list_master_keys(self) -> dict:
        """
        List all master keys in the vault.
        
        Returns a dictionary mapping fingerprints to peergroup names.
        """
        return {fp: data.get('peergroup') for fp, data in self.vault.items()}

    def get_peergroup(self, peergroup: str):
        """
        Query peergroup by ID or name.
        
        Process:
        1. Prevent access to protected tables (vault).
        2. If peergroup is a direct key in peer_table, return it.
        3. Otherwise, search by name and return matching entries.
        """
        if peergroup in self._protected_tables:
            raise ValueError(f"Access to {peergroup} is not permitted")
        if peergroup in self.peer_table:
            return {peergroup: self.peer_table[peergroup]}
        return {k: v for k, v in self.peer_table.items()
                if v['name'] == peergroup}

    def rename_peergroup(self, peergroup: str, new_name: str) -> None:
        """
        Rename a peergroup.
        
        Process:
        1. Validate that the peergroup exists.
        2. Update the name in the peergroup data.
        """
        if peergroup not in self.peer_table:
            raise ValueError(f'Peergroup {peergroup} not found')
        peergroup_data = self.peer_table[peergroup]
        peergroup_data['name'] = new_name
        self.peer_table[peergroup] = peergroup_data

    def get_user(self, peergroup: str, username: str,
                 get_key: bool = False):
        """
        Query user by username or fingerprint.
        
        Process:
        1. If peergroup is specified and exists:
           - Access the peergroup's user storage.
           - If username is a direct key, return the user data.
           - Otherwise, search users by username.
           - Remove key from results if not requested.
           - Merge with peergroup data.
        2. If peergroup is not specified or multiple match:
           - Get matching peergroups.
           - For each peergroup, perform the above query.
        """
        if peergroup in self.peer_table:
            self.pkns_table = self.db[peergroup]
            if username in self.pkns_table:
                res = {username: self.pkns_table[username]}
                if not get_key:
                    res[username].pop('key', None)
                res.update(self.peer_table[peergroup])
                return {peergroup: res}
            
            res = {k: v for k, v in self.pkns_table.items()
                   if v['username'] == username}
            if not get_key:
                for x in res:
                    res[x].pop('key', None)
            res.update(self.peer_table[peergroup])
            return {peergroup: res}
        
        peergroups = self.get_peergroup(peergroup)
        fres = {}
        for pg in peergroups:
            self.pkns_table = self.db[pg]
            if username in self.pkns_table:
                res = {username: self.pkns_table[username]}
                if not get_key:
                    res[username].pop('key', None)
                res.update(peergroups[pg])
                fres[pg] = res
            else:
                res = {k: v for k, v in self.pkns_table.items()
                       if v['username'] == username}
                if not get_key:
                    for x in res:
                        res[x].pop('key', None)
                res.update(peergroups[pg])
                fres[pg] = res
        return fres

    def get_all_users(self, peergroup: str, fingerprint_only: bool = True):
        """
        Get all users in a peergroup.
        
        Process:
        1. If peergroup is specified:
           - Access the peergroup's user storage.
           - If fingerprint_only, return list of keys.
           - Otherwise, return full user data merged with peergroup info.
        2. If multiple peergroups match:
           - For each, perform the above.
        """
        if peergroup in self.peer_table:
            self.pkns_table = self.db[peergroup]
            if fingerprint_only:
                result = list(self.pkns_table.keys())
                return result
            
            fres = {}
            fres[peergroup] = dict(self.pkns_table)
            fres.update(self.peer_table[peergroup])
            return fres
        
        peergroups = self.get_peergroup(peergroup)
        fres = {}
        for pg in peergroups:
            self.pkns_table = self.db[pg]
            fres[pg] = dict(self.pkns_table)
            if fingerprint_only:
                fres[pg] = list(self.pkns_table.keys())
            else:
                fres[pg].update(self.peer_table[pg])
        return fres

    def rename_user(self, peergroup: str, user: str, new_name: str):
        """
        Rename a user in a peergroup.
        
        Process:
        1. Validate peergroup exists.
        2. Access the peergroup's user storage.
        3. Validate user exists.
        4. Update the username in the user data.
        """
        if peergroup not in self.peer_table:
            raise ValueError(f'Peergroup {peergroup} not found')
        self.pkns_table = self.db[peergroup]
        if user not in self.pkns_table:
            raise ValueError(f'User {user} not found')
        user_data = self.pkns_table[user]
        user_data['username'] = new_name
        self.pkns_table[user] = user_data

    def resolve(self, query: dict) -> dict:
        """
        Resolve a PKNS query.
        
        Process:
        1. Extract peergroup and username from query.
        2. Prevent access to protected tables (vault) over network.
        3. Get matching peergroups (all if empty).
        4. Get matching users (all if empty, or specific).
        5. Merge peergroup and user data.
        """
        peergroup = query['peergroup']
        username = query['username']
        
        # Protect vault and system tables from network queries
        if peergroup in self._protected_tables:
            raise ValueError(f"Access to {peergroup} is not permitted")
        
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
        
        return dict_merge(rpeers, rusers)

    def sync(self, sync: dict) -> None:
        """
        Synchronize table entries.
        
        Process:
        1. For each entry in sync data:
           - If peergroup exists, update name and addresses.
           - If not, create new peergroup entry.
           - Remove processed fields from sync data.
        2. Parallelize user synchronization for each peergroup.
        """
        # First, process peergroup setups sequentially
        peergroup_sync_data = {}
        for x in sync:
            if x in self.peer_table:
                data = self.peer_table[x]
                data['name'] = sync[x]['name']
                if isinstance(sync[x]['address'], list):
                    data['address'].extend(sync[x]['address'])
                self.peer_table[x] = data
            else:
                if not isinstance(sync[x]['address'], list):
                    sync[x]['address'] = list(set(sync[x]['address']))
                self.peer_table[x] = {}
                self.peer_table[x]['name'] = sync[x]['name']
                self.peer_table[x]['address'] = sync[x]['address']
            sync[x].pop('name', None)
            sync[x].pop('address', None)
            peergroup_sync_data[x] = sync[x]
        
        # Now parallelize user synchronization
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(self.sync_users, peergroup_sync_data[x], x)
                for x in peergroup_sync_data
            ]
            # Wait for all to complete
            for future in futures:
                future.result()

    def sync_users(self, sync: dict, peergroup: str):
        """
        Synchronize user entries in a peergroup.
        
        Process:
        1. Access the peergroup's user storage.
        2. For each user in sync data:
           - If user exists, update addresses.
           - If not, create new user entry.
        """
        self.pkns_table = self.db[peergroup]
        for x in sync:
            if x in self.pkns_table:
                data = self.pkns_table[x]
                if isinstance(sync[x]['address'], list):
                    data['address'].extend(sync[x]['address'])
                self.pkns_table[x] = data
            else:
                if not isinstance(sync[x]['address'], list):
                    sync[x]['address'] = [sync[x]['address']]
                self.pkns_table[x] = sync[x]


# Backwards compatibility alias
PKNS_Table = PKNSTable
