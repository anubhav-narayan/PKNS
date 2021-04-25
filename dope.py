'''
DOPE Class
'''


__version__ = "2.0.3"
__author__ = "Anubhav Mattoo"

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Hash import HMAC, SHA256, SHA384, SHA512
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss, pkcs1_15
import bchlib
import base64
from typing import Union
from hashlib import blake2b, blake2s
from pickle5 import loads, dumps
from gzip import compress, decompress

# Lookup Tables
AES_MODE_LOOKUP = {
	"GCM" : AES.MODE_GCM,
	"SIV" : AES.MODE_SIV,
	"CBC" : AES.MODE_CBC,
	"OFB" : AES.MODE_OFB
}
RATCHET_MODE_LOOKUP = {
	"BLAKE0x0" : 0x0,
	"BLAKEx0x" : 0x1,
}
HMAC_LOOKUP = {
	"SHA256" : SHA256,
	"SHA384" : SHA384,
	"SHA512" : SHA512
}
HMAC_SIZE_LOOKUP = {
	1024 : 128,
	2048 : 256,
	3072 : 384,
	4096 : 512,
	8192 : 1024
}
KEY_MODE_LOOKUP = {
	"XOR-BL" : 0x0,
	"AND-BL" : 0x1,
}
DOPE_HIGHER_LOOKUP = {
	# Higher Byte
	(1024, "GCM", "BLAKE0x0") : b'\x00',
	(1024, "GCM", "BLAKEx0x") : b'\x01',
	(1024, "SIV", "BLAKE0x0") : b'\x04',
	(1024, "SIV", "BLAKEx0x") : b'\x05',
	(1024, "CBC", "BLAKE0x0") : b'\x08',
	(1024, "CBC", "BLAKEx0x") : b'\x09',
	(1024, "OFB", "BLAKE0x0") : b'\x0C',
	(1024, "OFB", "BLAKEx0x") : b'\x0D',

	(2048, "GCM", "BLAKE0x0") : b'\x10',
	(2048, "GCM", "BLAKEx0x") : b'\x11',
	(2048, "SIV", "BLAKE0x0") : b'\x14',
	(2048, "SIV", "BLAKEx0x") : b'\x15',
	(2048, "CBC", "BLAKE0x0") : b'\x18',
	(2048, "CBC", "BLAKEx0x") : b'\x19',
	(2048, "OFB", "BLAKE0x0") : b'\x1C',
	(2048, "OFB", "BLAKEx0x") : b'\x1D',

	(4096, "GCM", "BLAKE0x0") : b'\x20',
	(4096, "GCM", "BLAKEx0x") : b'\x21',
	(4096, "SIV", "BLAKE0x0") : b'\x24',
	(4096, "SIV", "BLAKEx0x") : b'\x25',
	(4096, "CBC", "BLAKE0x0") : b'\x28',
	(4096, "CBC", "BLAKEx0x") : b'\x29',
	(4096, "OFB", "BLAKE0x0") : b'\x2C',
	(4096, "OFB", "BLAKEx0x") : b'\x2D',
}
INV_DOPE_HIGHER_LOOKUP = {
	# Higher Byte
	0x00 : (1024, "GCM", "BLAKE0x0"),
	0x01 : (1024, "GCM", "BLAKEx0x"),
	0x04 : (1024, "SIV", "BLAKE0x0"),
	0x05 : (1024, "SIV", "BLAKEx0x"),
	0x08 : (1024, "CBC", "BLAKE0x0"),
	0x09 : (1024, "CBC", "BLAKEx0x"),
	0x0C : (1024, "OFB", "BLAKE0x0"),
	0x0D : (1024, "OFB", "BLAKEx0x"),

	0x10 : (2048, "GCM", "BLAKE0x0"),
	0x11 : (2048, "GCM", "BLAKEx0x"),
	0x14 : (2048, "SIV", "BLAKE0x0"),
	0x15 : (2048, "SIV", "BLAKEx0x"),
	0x18 : (2048, "CBC", "BLAKE0x0"),
	0x19 : (2048, "CBC", "BLAKEx0x"),
	0x1C : (2048, "OFB", "BLAKE0x0"),
	0x1D : (2048, "OFB", "BLAKEx0x"),

	0x20 : (4096, "GCM", "BLAKE0x0"),
	0x21 : (4096, "GCM", "BLAKEx0x"),
	0x24 : (4096, "SIV", "BLAKE0x0"),
	0x25 : (4096, "SIV", "BLAKEx0x"),
	0x28 : (4096, "CBC", "BLAKE0x0"),
	0x29 : (4096, "CBC", "BLAKEx0x"),
	0x2C : (4096, "OFB", "BLAKE0x0"),
	0x2D : (4096, "OFB", "BLAKEx0x"),
}
DOPE_LOWER_LOOKUP = {
	# Lower Byte
	("SHA256", "XOR-BL") : b'\x00',
	("SHA256", "AND-BL") : b'\x01',

	("SHA384", "XOR-BL") : b'\x10',
	("SHA384", "AND-BL") : b'\x11',

	("SHA512", "XOR-BL") : b'\x20',
	("SHA512", "AND-BL") : b'\x21',
}
INV_DOPE_LOWER_LOOKUP = {
	# Lower Byte
	0x00 : ("SHA256", "XOR-BL"),
	0x01 : ("SHA256", "AND-BL"),

	0x10 : ("SHA384", "XOR-BL"),
	0x11 : ("SHA384", "AND-BL"),

	0x20 : ("SHA512", "XOR-BL"),
	0x21 : ("SHA512", "AND-BL"),
}



def oaep_encrypt(key, data:bytes) -> bytes:
	'''
	PKCSv1.5 Encryption
	'''
	encryptor = PKCS1_v1_5.new(key)
	return encryptor.encrypt(data)


def oaep_decrypt(key, data:bytes) -> bytes:
	'''
	PKCSv1.5 Decryption
	'''
	decryptor = PKCS1_v1_5.new(key)
	return decryptor.decrypt(data, None)


def byte_xor(left:bytes, right:bytes) -> bytes:
	'''
	XOR Byte String, 2 input
	'''
	return bytes([a ^ b for a, b in zip(left, right)])


def byte_and(left:bytes, right:bytes) -> bytes:
	'''
	AND Byte String, 2 inputs
	'''
	return bytes([a & b for a, b in zip(left, right)])


class DOPE():
	"""
	Double Ratchet Over Parity Exchange(DOPE)
	System Class for DOPE
	Parameters:-
		key : PublicKey.RSA
		end_key : PublicKey.RSA
		bch_poly : int
		ecc_size : int
		aes_mode : str
		ratchet_mode : str
		hmac : str
		key_mode : str

	Labels:-
		end_key : Reciever's Public Key
		key : Sender's Key-Pair
		rsa : Sender's Session Key-Pair
		pan_key : Reciever's Session Public Key
		bch_poly : BCH Polynomial
		ecc_size : Number of Error to Correct
	"""
	def __init__(self, key : RSA.RsaKey, end_key : RSA.RsaKey,
				rsa_size:int, bch_poly:int,
				ecc_size:int, ratchet_mode:str,
				aes_mode:str, hmac:str, key_mode:str):
		self.key_version = 0
		self.__ratchet_home = 0
		self.__ratchet_end = 0
		self.key = key
		self.end_key = end_key
		self.__rsa_size = rsa_size
		self.__bch = bchlib.BCH(bch_poly, ecc_size)
		self.__bch_poly = bch_poly
		if aes_mode in AES_MODE_LOOKUP:
			self.__aes_mode = aes_mode
			if aes_mode == "SIV":
				self.__aes_size = 512
			else:
				self.__aes_size = 256 
		else:
			raise TypeError(f"DOPE does not support {aes_mode} mode")
		if ratchet_mode in RATCHET_MODE_LOOKUP:
			self.__ratchet_mode = ratchet_mode
		else:
			raise TypeError(f"DOPE does not support {ractchet_mode} mode")
		if hmac in HMAC_LOOKUP:
			self.__hmac = hmac
		else:
			raise TypeError(f"DOPE does not support {hmac} mode")
		if key_mode in KEY_MODE_LOOKUP:
			self.__key_mode = key_mode
		else:
			raise TypeError(f"DOPE does not support {key_mode} mode")
		pass


	def __str__(self):
		DOPE = f'DOPE_{self.__ratchet_mode}_{self.__key_mode}_'
		RSA = f'RSA_{self.__rsa.size_in_bits()}_'
		BCH = f'BCH_{self.__bch.t}_{self.__bch.ecc_bytes}_'
		AES = f'AES_{self.__aes_size}_{self.__aes_mode}_'
		HMAC = f'{self.__hmac}'
		return DOPE + RSA + BCH + AES + HMAC


	def __repr__(self):
		return self.__str__()	


	def generate_key(self) -> bytes:
		'''
		Generate a DOPE Key Packet for the current configuration
		'''
		self.__rsa = RSA.generate(self.__rsa_size)
		self.__ratchet_home = 0
		self.__ratchet_end = 0
		self.key_version += 1
		if self.key_version >= 256:
			raise ValueError("DOPE Keys Exhausted")
		version = self.key_version.to_bytes(4, 'big')
		p_flags_h = DOPE_HIGHER_LOOKUP[(self.__rsa.size_in_bits(), self.__aes_mode, self.__ratchet_mode)]
		p_flags_l = DOPE_LOWER_LOOKUP[(self.__hmac, self.__key_mode)]
		p_flags = p_flags_h + p_flags_l
		rsa_public_oaep = oaep_encrypt(self.end_key, self.__rsa.publickey().export_key())
		hash_val = HMAC_LOOKUP[self.__hmac].new(rsa_public_oaep)
		hmac = pkcs1_15.new(self.key).sign(hash_val)
		pad_len = ((len(rsa_public_oaep+hmac) + 8) % 1280)
		padding = get_random_bytes(pad_len)
		pad_len = pad_len.to_bytes(2, 'big')
		data = version+pad_len+p_flags+rsa_public_oaep+hmac+padding
		ecc = self.__bch.encode(data)
		data = data + ecc
		data = base64.urlsafe_b64encode(data)
		if len(data) >= 80:
			data = b"".join(data[i:i+80] + b"\n" for i in range(0,len(data),80))
		self.__dope_key = b'-----BEGIN DOPE KEY-----\n' + data + b'-----END DOPE KEY-----'
		return self.__dope_key


	@property
	def DOPE_key(self) -> bytes:
		return self.__dope_key


	def verify_key(self, dope:bytes):
		'''
		Unpack and Verfy DOPE Key as per policy
		'''
		dope = dope.splitlines()[1:-1]
		dope = b"".join(dope)
		dope = base64.urlsafe_b64decode(dope)
		decoder = self.__bch
		data, ecc = dope[:-decoder.ecc_bytes], dope[-decoder.ecc_bytes:]
		flips, data, ecc = decoder.decode(data, ecc)
		version, pad_len, p_flags, data = data[:4], data[4:6], data[6:8], data[8:]
		pad_len = int.from_bytes(pad_len, 'big')
		data = data[:-pad_len]
		p_flags_l = INV_DOPE_LOWER_LOOKUP[p_flags[1]]
		p_flags_h = INV_DOPE_HIGHER_LOOKUP[p_flags[0]]
		hmac_size = HMAC_SIZE_LOOKUP[self.end_key.size_in_bits()]
		session_key, hmac = data[:-hmac_size], data[-hmac_size:]
		hash_val = HMAC_LOOKUP[p_flags_l[0]].new(session_key)
		try:
			pkcs1_15.new(self.end_key).verify(hash_val, hmac)
			session_key = oaep_decrypt(self.key, session_key)
			self.__pan_key = RSA.import_key(session_key)
			self.__end_param = {
				"S_KEY" : bytes(session_key),
				"HMAC" : bytes(hmac),
				"LFLAG" : p_flags_l,
				"HFLAG" : p_flags_h,
				"KEY_VER" : int.from_bytes(version, byteorder='big'),
				"ECC" : ecc
			}
			return self.__end_param
		except:
			raise


	def fixate(self, dope:bytes):
		'''
		Fixate at a key and Start Ratchets
		'''
		self.verify_key(dope)
		if self.__key_mode == 'XOR-BL':
			# Key = BLAKE(BLAKE(Weak Home) XOR BLAKE(Strong Home))
			weak_home = blake2b(self.__rsa.publickey().export_key()).digest()
			strong_home = blake2b(self.key.publickey().export_key()).digest()
			if self.__aes_mode == "SIV":
				self.__hkdf_home = blake2b(byte_xor(weak_home, strong_home))
			else:
				self.__hkdf_home = blake2b(byte_xor(weak_home, strong_home), digest_size=32)

		if self.__end_param['LFLAG'][1] == 'XOR-BL':
			# Key = BLAKE(BLAKE(Weak End) XOR BLAKE(Strong End))
			weak_end = blake2b(self.__pan_key.export_key()).digest()
			strong_end = blake2b(self.end_key.export_key()).digest()
			if self.__end_param['HFLAG'][1] == "SIV":
				self.__hkdf_end = blake2b(byte_xor(weak_end, strong_end))
			else:
				self.__hkdf_end = blake2b(byte_xor(weak_end, strong_end), digest_size=32)


		if self.__key_mode == 'AND-BL':
			# Key = BLAKE(BLAKE(Weak Home) AND BLAKE(Strong Home))
			weak_home = blake2b(self.__rsa.publickey().export_key()).digest()
			strong_home = blake2b(self.key.publickey().export_key()).digest()
			if self.__aes_mode == "SIV":
				self.__hkdf_home = blake2b(byte_and(weak_home, strong_home))
			else:
				self.__hkdf_home = blake2b(byte_and(weak_home, strong_home), digest_size=32)

		if self.__end_param['LFLAG'][1] == 'AND-BL':
			# Key = BLAKE(BLAKE(Weak End) AND BLAKE(Strong End))
			weak_end = blake2b(self.__pan_key.export_key()).digest()
			strong_end = blake2b(self.end_key.export_key()).digest()
			if self.__end_param['HFLAG'][1] == "SIV":
				self.__hkdf_end = blake2b(byte_and(weak_end, strong_end))
			else:
				self.__hkdf_end = blake2b(byte_and(weak_end, strong_end), digest_size=32)

		# self.__hkdf_home.update(self.__end_param['ECC'])
		# self.__hkdf_end.update(self.__dope_key[-self.__bch.ecc_bytes:])


	def ratchet_home(self, ecc:bytes):
		'''
		Ratchet to Next Home Key
		'''
		self.__ratchet_home += 1
		if self.__ratchet_home > 2 ** 128:
			raise ValueError('Keys Exhausted')
		key = self.__hkdf_home.digest()
		self.__hkdf_home.update(key + bytes(ecc))

	def key_home(self) -> bytes:
		'''
		Ratchet to Next Home Key
		'''
		if self.__ratchet_home > 2 ** 128:
			raise ValueError('Keys Exhausted')
		key = self.__hkdf_home.digest()
		return key


	def ratchet_end(self, ecc:bytes):
		'''
		Ratchet to Next End Key
		'''
		self.__ratchet_end += 1
		if self.__ratchet_end > 2 ** 128:
			raise ValueError('Keys Exhausted')
		key = self.__hkdf_end.digest()
		self.__hkdf_end.update(key + bytes(ecc))


	def key_end(self) -> bytes:
		'''
		Ratchet to Next End Key
		'''
		if self.__ratchet_end > 2 ** 128:
			raise ValueError('Keys Exhausted')
		key = self.__hkdf_end.digest()
		return key


	def pack_data(self, data:bytes):
		'''
		Pack Data to DOPE Standard
		'''
		data_block = []
		for x in range(0, len(data), 1280):
			pad_len = 0
			if len(data[x:x+1280]) < 1280:
				pad_len = 1280 - len(data[x:x+1280])
			data_x = data[x:x+1280] + get_random_bytes(pad_len)
			pad_len = pad_len.to_bytes(4, 'big')
			data_block.append(pad_len + data_x)
		return data_block


	def encode(self, data:bytes) -> bytes:
		'''
		Encode Data in DOPE Data format
		and Serialise as a byte string 
		'''
		data_block = self.pack_data(data)
		code_string = []
		counter = -1
		for x in data_block: # x : Data Batch
			counter += 1
			key = self.key_end()
			ecc = self.__bch.encode(x[4:])
			if self.__end_param['HFLAG'][1] in ['SIV', 'GCM']:
				nonce = get_random_bytes(16)
				encoder = AES.new(key, AES_MODE_LOOKUP[self.__end_param['HFLAG'][1]], nonce=nonce)
				encoder.update(b'DOPE')
				header = b'DOPE' + nonce
				data, tag = encoder.encrypt_and_digest(x[4:])
				header = oaep_encrypt(self.__pan_key, header)
				if self.__end_param['HFLAG'][2][-3:] == '0x0':
					packet = {
						'block' : counter,
						'header' : header,
						'pad_len' : x[:4],
						'data' : data,
						'tag' : tag,
						'ecc' : self.__bch.encode(data)
					}
					code_string.append(dumps(packet))
				else:
					packet = {
						'block' : counter,
						'header' : header,
						'pad_len' : x[:4],
						'data' : data,
						'tag' : tag,
						'ecc' : ecc
					}
					code_string.append(dumps(packet))
			else:
				encoder = AES.new(key, AES_MODE_LOOKUP[self.__end_param['HFLAG'][1]])
				header = b'DOPE' + encoder.iv
				data = encoder.encrypt(x[4:])
				header = oaep_encrypt(self.__pan_key, header)
				if self.__end_param['HFLAG'][2][-3:] == '0x0':
					packet = {
						'block' : counter,
						'header' : header,
						'pad_len' : x[:4],
						'data' : data,
						'ecc' : self.__bch.encode(data)
					}
					code_string.append(dumps(packet))
				else:
					packet = {
						'block' : counter,
						'header' : header,
						'pad_len' : x[:4],
						'data' : data,
						'ecc' : ecc
					}
					code_string.append(dumps(packet))
		packets = dumps(code_string)
		packets_ecc = self.__bch.encode(packets)
		self.ratchet_end(packets_ecc)
		return compress(packets + packets_ecc)



	def decode(self, data:bytes) -> bytes:
		'''
		Decode Data in DOPE Data format
		by marshalling the byte string
		'''
		pacl = self.__bch
		data = decompress(data)
		packet, packet_ecc = data[:-pacl.ecc_bytes], data[-pacl.ecc_bytes:]
		flips, packet, packet_ecc = self.__bch.decode(packet, packet_ecc)
		code_string = loads(packet)
		data = b''
		for x in code_string:
			key = self.key_home()
			packet = loads(x)
			if self.__aes_mode in ['SIV', 'GCM']:
				header = oaep_decrypt(self.__rsa, packet['header'])
				decoder = AES.new(key, AES_MODE_LOOKUP[self.__aes_mode], nonce=header[4:])
				decoder.update(header[:4])
				p_data = decoder.decrypt_and_verify(packet['data'], packet['tag'])
				if self.__ratchet_mode[-3:] == '0x0':
					_, p_data, ecc = self.__bch.decode(p_data, packet['ecc'])
				p_data = p_data[:1280 - int.from_bytes(packet['pad_len'], 'big')]
				if self.__ratchet_mode[-3:] == 'x0x':
					_, p_data, ecc = self.__bch.decode(p_data, packet['ecc'])
				data += p_data
			else:
				header = oaep_decrypt(self.__rsa, packet['header'])
				decoder = AES.new(key, AES_MODE_LOOKUP[self.__aes_mode], iv=header[4:])
				p_data = decoder.decrypt(packet['data'])
				if self.__ratchet_mode[-3:] == '0x0':
					_, p_data, ecc = self.__bch.decode(p_data, packet['ecc'])
				p_data = p_data[:1280 - int.from_bytes(packet['pad_len'], 'big')]
				if self.__ratchet_mode[-3:] == 'x0x':
					_, p_data, ecc = self.__bch.decode(p_data, packet['ecc'])
				data += p_data
		self.ratchet_home(packet_ecc)
		return data


class DOPE2(object):
	"""
	Double Ratchet Over Parity Exchange(DOPE)
	System Class for DOPE
	Parameters:-
		key : bytes
		bch_poly : int
		ecc_size : int
		aes_mode : str
		ratchet_mode : str
	"""
	def __init__(self, key : bytes, bch_poly : int,
				 ecc_size : int, aes_mode : str,
				 nonce : bytes, block_size : int = 512):
		self.__key = key
		self.__bch = bchlib.BCH(bch_poly, ecc_size)
		self.__bch_poly = bch_poly
		self.___fixture = False
		if len(nonce) == 0:
			self.__nonce = get_random_bytes(32)
		elif len(nonce) <= 32:
			self.__nonce = blake2s(nonce, digest_size=32)
		elif len(nonce) == 32:
			self.__nonce = nonce
		else:
			raise TypeError(f"DOPE does not support nonce of size {len(nonce)}")
		self.__ratchet_count = 0
		if block_size >= 512:
			self.block_size = block_size
		else:
			raise TypeError(f"DOPE does not support block size{block_size}, block must be greater than 512")
		if aes_mode in AES_MODE_LOOKUP:
			self.__aes_mode = aes_mode
			if aes_mode == "SIV":
				self.__aes_size = 512
			else:
				self.__aes_size = 256
		else:
			raise TypeError(f"DOPE does not support {aes_mode} mode")


	def __str__(self):
		DOPE = f'DOPE2_'
		BCH = f'BCH_{self.__bch.t}_{self.__bch.ecc_bytes}_'
		AES = f'AES_{self.__aes_size}_{self.__aes_mode}_'
		BLK = f'BLK_{self.block_size}'
		return DOPE + BCH + AES + BLK


	def __repr__(self):
		return self.__str__()


	def serialize(self):
		khac = blake2b(self.__key, digest_size=32).digest()
		nhac = blake2b(self.__nonce, digest_size=32).digest()
		kvac = blake2b(khac + nhac).digest()
		data = self.block_size.to_bytes(16, 'big') + self.__bch_poly.to_bytes(16, 'big') + self.__bch.t.to_bytes(16, 'big') + self.__nonce
		if self.__aes_mode in ['SIV', 'GCM']:
			nonce = get_random_bytes(16)
			encoder = AES.new(khac , AES_MODE_LOOKUP[self.__aes_mode], nonce=nonce)
			encoder.update(nonce)
			data, tag = encoder.encrypt_and_digest(data)
			data = nonce + data + tag
		else:
			encoder = AES.new(khac, AES_MODE_LOOKUP[self.__aes_mode])
			data = encoder.iv + encoder.encrypt(data)
		data = self.__aes_mode.encode('utf8') + data + kvac
		data = base64.urlsafe_b64encode(data)
		if len(data) >= 80:
			data = b"".join(data[i:i+80] + b"\n" for i in range(0,len(data),80))
		data = b'-----BEGIN DOPE 2 KEY-----\n' + data + b'-----END DOPE 2 KEY-----'
		return data

	@classmethod
	def marshall(cls, key : Union[str, bytes], password : bytes):
		khac = blake2b(password, digest_size=32).digest()
		data = key.splitlines()[1:-1]
		data = b"".join(data)
		data = base64.urlsafe_b64decode(data)
		aes_mode, niv, data, kvac = data[:3].decode('utf8') , data[3:19], data[19:-64], data[-64:]
		if aes_mode in ['SIV', 'GCM']:
			decoder = AES.new(khac, AES_MODE_LOOKUP[aes_mode], nonce=niv)
			decoder.update(niv)
			data = decoder.decrypt_and_verify(data[:-16], data[-16:])
		else:
			decoder = AES.new(khac, AES_MODE_LOOKUP[aes_mode], iv=niv)
			data = decoder.decrypt(data)
		block_size, bch_poly, ecc_size, nonce = int.from_bytes(data[:16], 'big'), int.from_bytes(data[16:32], 'big'), int.from_bytes(data[32:48], 'big'), data[48:]
		nhac = blake2b(nonce, digest_size=32).digest()
		vkac = blake2b(khac + nhac).digest()
		if vkac != kvac:
			raise ValueError('Key Verification Error')
		return cls(password, bch_poly, ecc_size, aes_mode, nonce, block_size)


	def fixate(self):
		'''
		Fixate at a key and Start Ratchets
		'''
		# Key = BLAKE(BLAKE(Weak Home) XOR BLAKE(Strong Home))
		self.__fixture = True
		hash_pass = blake2b(self.__key).digest()
		hash_nonce = blake2b(self.__nonce).digest()
		if self.__aes_mode == "SIV":
			self.__hkdf = blake2b(byte_xor(hash_pass, hash_nonce))
		else:
			self.__hkdf = blake2b(byte_xor(hash_pass, hash_nonce), digest_size=32)



	@property
	def nonce(self):
		return self.__nonce


	def ratchet(self, ecc:bytes):
		'''
		Ratchet to Next Key
		'''
		self.__ratchet_count += 1
		if self.__ratchet_home > 2 ** 128:
			raise ValueError('Keys Exhausted')
		key = self.__hkdf.digest()
		self.__hkdf.update(key + bytes(ecc))


	def key(self) -> bytes:
		'''
		Ratchet to Next Home Key
		'''
		if self.__ratchet_count > 2 ** 128:
			raise ValueError('Keys Exhausted')
		key = self.__hkdf.digest()
		return key

	def pack_data(self, data:bytes) -> list:
		'''
		Pack Data to DOPE Standard
		'''
		data_block = []
		for x in range(0, len(data), self.block_size - 4):
			pad_len = 0
			if len(data[x:x+self.block_size - 4]) < self.block_size - 4:
				pad_len = self.block_size - 4 - len(data[x:x+self.block_size - 4])
			data_x = data[x:x+self.block_size - 4] + get_random_bytes(pad_len)
			pad_len = pad_len.to_bytes(4, 'big')
			data_block.append(pad_len + data_x)
		return data_block


	def encode(self, data:bytes) -> bytes:
		'''
		Encode Data in DOPE Data format
		and Serialise as a byte string 
		'''
		if not self.__fixture:
			self.fixate()
		data_block = self.pack_data(data)
		code_string = []
		counter = -1
		for x in data_block: # x : Data Batch
			counter += 1
			key = self.key()
			ecc = self.__bch.encode(x[4:])
			if self.__aes_mode in ['SIV', 'GCM']:
				nonce = get_random_bytes(16)
				encoder = AES.new(key, AES_MODE_LOOKUP[self.__aes_mode], nonce=nonce)
				encoder.update(b'DOPE')
				header = b'DOPE' + nonce
				data, tag = encoder.encrypt_and_digest(x[4:])
				packet = {
					'block' : counter,
					'header' : header,
					'pad_len' : x[:4],
					'data' : data,
					'tag' : tag,
					'ecc' : self.__bch.encode(data)
				}
				code_string.append(dumps(packet))
			else:
				encoder = AES.new(key, AES_MODE_LOOKUP[self.__aes_mode])
				header = b'DOPE' + encoder.iv
				data = encoder.encrypt(x[4:])
				packet = {
					'block' : counter,
					'header' : header,
					'pad_len' : x[:4],
					'data' : data,
					'ecc' : self.__bch.encode(data)
				}
				code_string.append(dumps(packet))
				self.ratchet(packet['ecc'])
		packets = dumps(code_string)
		packets_ecc = self.__bch.encode(packets)
		self.__fixture = False
		return compress(packets + packets_ecc)


	def decode(self, data : bytes, start : int, end : int) -> bytes:
		'''
		Decode Data in DOPE Data format
		by marshalling the byte string
		'''
		if not self.__fixture:
			self.fixate()
		pacl = self.__bch
		data = decompress(data)
		aes_mode, nonce, packet, packet_ecc = data[:-pacl.ecc_bytes], data[-pacl.ecc_bytes:]
		flips, packet, packet_ecc = self.__bch.decode(packet, packet_ecc)
		code_string = loads(packet)
		data = b''
		for x in code_string:
			key = self.key()
			packet = loads(x)
			if self.__aes_mode in ['SIV', 'GCM']:
				header = packet['header']
				decoder = AES.new(key, AES_MODE_LOOKUP[self.__aes_mode], nonce=header[4:])
				decoder.update(header[:4])
				p_data = decoder.decrypt_and_verify(packet['data'], packet['tag'])
				_, p_data, ecc = self.__bch.decode(p_data, packet['ecc'])
				data += p_data
			else:
				decoder = AES.new(key, AES_MODE_LOOKUP[self.__aes_mode], iv=header[4:])
				p_data = decoder.decrypt(packet['data'])
				_, p_data, ecc = self.__bch.decode(p_data, packet['ecc'])
				data += p_data
			self.ratchet(packet['ecc'])
		self.__fixture = False
		return data