import Crypto.Signature.PKCS1_v1_5 as sign_PKCS1_v1_5
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA

from loopyCryptor.Serializer import *


class Cryptor:
    """Cryptor is based on AES-CBC-16 and RSA_PKCS"""

    __default_AES_key = None
    __default_RSA_key = (None, None)

    def __init__(self):
        """
        init func
        :raise AttributeError: should not be instance
        """
        raise AttributeError("Cryptor should not be instance")

    @staticmethod
    def _validate_key(key):
        """
        check if key is not None

        :param key:
        :return: key
        :raise AttributeError: No valid key was passed in
        """

        if key is None:
            raise AttributeError("No valid key was passed in")
        return to_byte(key, force_convert=False)

    @classmethod
    def set_default_AES_key(cls, AES_key: bytes or str):
        """
        set a default AES_key, which store in Class-variable:__default_AES_key.

        :param AES_key: bytes/string AES_key
        """
        cls.__default_AES_key = to_byte(AES_key, force_convert=False)

    @classmethod
    def set_default_RSA_key(cls, public_key: bytes or str, private_key: bytes or str):
        """
        set a pair of default RSA_key, which store in Class-variable:__default_RSA_key.

        :param public_key:
        :param private_key:
        :return:
        """
        cls.__default_RSA_key = (to_byte(public_key, force_convert=False), to_byte(private_key, force_convert=False))

    @classmethod
    def generate_RSA_key(cls, set_default=False):
        """
        generate a RSA key pair

        :param set_default:set the key for default
        :return: bytes
        """
        rsa = RSA.generate(1024, Random.new().read)
        private_pem = rsa.exportKey()
        public_pem = rsa.publickey().exportKey()
        if set_default:
            cls.set_default_RSA_key(public_pem, private_pem)
        return public_pem, private_pem

    @classmethod
    def generate_AES_key(cls, set_default=False):
        """
        Generate a AES key

        :param set_default:set the key for default
        :return key: byte
        """
        key = Random.get_random_bytes(16)
        if set_default:
            cls.set_default_AES_key(key)
        return key

    @classmethod
    def AES_encrypt(cls, obj, key: bytes or str = None):
        """
        Encrypt: Encode the object into a byte-stream, then add it to a multiple of 16, then obtained a \
        symmetric encryption key that is updated daily and then encrypt the string with the key.It is worth noting \
        that '\0' is used in the completion.

        :param obj: Any kind of object to be encrypted
        :param key: byte AES key
        :return: byte Encrypted byte stream
        """
        byte = to_byte(obj)
        key = Cryptor._validate_key(cls.__default_AES_key if key is None else key)
        byte += b"\0" * (16 - (len(byte) % 16))
        return AES.new(key, AES.MODE_CBC, key).encrypt(byte)

    @classmethod
    def AES_decrypt(cls, byte: bytes or str, key: bytes or str = None):
        """
        Decrypt: Obtained the symmetric encrypted key, decrypt the byte stream and removed '\0',finally decoded\
         it into a string

        :param byte: byte/string Bytes/string to be decrypted
        :param key: byte AES key
        :return: Decrypted object
        """
        byte = to_byte(byte, force_convert=False)
        key = Cryptor._validate_key(cls.__default_AES_key if key is None else key)
        plain_byte = AES.new(key, AES.MODE_CBC, key).decrypt(byte)

        return to_obj(plain_byte.rstrip(b"\0"))

    @classmethod
    def RSA_encrypt(cls, obj, key: bytes or str = None):
        """
        Encrypt: import a RSA key and use it to encrypt text

        :param obj: Any kind of object to be encrypted
        :param key: byte RSA key
        :return: byte Encrypted byte stream
        """
        bytes = to_byte(obj)
        bytes_list = cut_bytes(bytes)

        key = Cryptor._validate_key(
            key if key is not None else cls.__default_RSA_key[0]
        )
        PKCS1 = PKCS1_v1_5.new(RSA.importKey(key))

        cipher_bytes_list = map(lambda x: PKCS1.encrypt(x), bytes_list)
        return concat_byte_list(cipher_bytes_list)

    @classmethod
    def RSA_decrypt(cls, byte, key=None):
        """
        Decrypt: import a RSA public key and use it to decrypt text

        :param byte: byte/string Bytes/string to be decrypted
        :param key: byte RSA private_key
        :return: Decrypted object
        """
        byte_list = to_byte(byte, force_convert=False).split(b'[BRK]')[:-1]
        key = Cryptor._validate_key(
            key if key is not None else cls.__default_RSA_key[1]
        )
        PKCS1 = PKCS1_v1_5.new(RSA.importKey(key))
        bytes_list = map(lambda x: PKCS1.decrypt(x, "ERROR"), byte_list)
        return to_obj(concat_byte_list(bytes_list, add_break=False))

    @classmethod
    def RSA_sign(cls, obj, key: bytes or str = None):
        key = Cryptor._validate_key(
            key if key is not None else cls.__default_RSA_key[1]
        )
        PKCS1 = sign_PKCS1_v1_5.new(RSA.importKey(key))
        return PKCS1.sign(Cryptor.md5(obj, ret_hex=False))

    @classmethod
    def RSA_verify(cls, obj, signature, key: bytes or str = None):
        key = Cryptor._validate_key(
            key if key is not None else cls.__default_RSA_key[0]
        )
        PKCS1 = sign_PKCS1_v1_5.new(RSA.importKey(key))
        return PKCS1.verify(Cryptor.md5(obj, ret_hex=False), signature)

    @staticmethod
    def md5(obj, ret_hex=True):
        """
        Run md5: If content is a list, it will update multiple times in items. Or it will return md5(content).

        :param obj: list/byte/str If it's a list, it will update multiple times in items.
        :param ret_hex: return hexdigest, or it will return a md5 obj
        :return: str/md5 md5 result
        """
        md5_ = MD5.new()

        if isinstance(obj, list):
            for item in obj:
                md5_.update(to_byte(item))
        elif len(to_byte(obj)) > 500:
            return Cryptor.md5(cut_bytes(to_byte(obj), cut_length=500), ret_hex=ret_hex)
        else:
            md5_.update(to_byte(obj))
        return md5_.hexdigest() if ret_hex else md5_
