'''
PKNS Class
'''

__version__ = "0.0.1"
__author__ = "Anubhav Mattoo"


class PKNS():
	"""
	Public Key Name System
	"""
	def __init__(self):
		self.pkns_table = {}
		self.pkns_name = {}
		pass

	def __repr__(self):
		retstr = ''
		for x in self.pkns_table:
			retstr += f'{x} - {self.pkns_table[x]} - {self.pkns_name[self.pkns_table[x]]}\n'
		if len(retstr) != 0:
			return retstr
		return "EMPTY"


	def add_entry(self, key : bytes, username : dict, address : tuple) -> None :
		'''
		Add or Update Entry in the Table
		'''
		if key in self.pkns_table and username != self.pkns_table[key]:
			raise ValueError("Invalid Key")
		if key in self.pkns_table and username == self.pkns_table[key] and username in self.pkns_name:
			self.add_address(username, address)
			return
		self.pkns_table[key] = username
		self.pkns_name[username] = []
		self.pkns_name[username].append(address)


	def add_address(self, username : str, address : tuple) -> None :
		'''
		Add or Update Addresses in the Table
		'''
		self.pkns_table[username].append(address)


	def purge_entry(self, key : bytes) -> None:
		'''
		Purge from Table
		'''
		if key not in self.pkns_table:
			raise ValueError("Invalid Key")
		self.pkns_name.pop(self.pkns_table[key])
		self.pkns_table.pop(key)