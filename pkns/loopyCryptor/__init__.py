try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto import Random
    from Crypto.PublicKey import RSA
except:
    raise ImportError(
        "LoopyCryptor depends on Crypto, "
        "which was not found, please `pip install pycryptodome`.\n"
        "If there's still an error, please go to "
        "https://pycryptodome.readthedocs.io/en/latest/src/installation.html"
        "to make sure you have successfully install Crypto"
    )

from .Cryptor import Cryptor

set_default_AES_key = Cryptor.set_default_AES_key
set_default_RSA_key = Cryptor.set_default_RSA_key

generate_RSA_key = Cryptor.generate_RSA_key
generate_AES_key = Cryptor.generate_AES_key

AES_encrypt = Cryptor.AES_encrypt
AES_decrypt = Cryptor.AES_decrypt
RSA_encrypt = Cryptor.RSA_encrypt
RSA_decrypt = Cryptor.RSA_decrypt

md5 = Cryptor.md5
sign = Cryptor.RSA_sign
verify = Cryptor.RSA_verify


def encrypt(obj, method="AES", key=None):
    if method == "AES":
        return AES_encrypt(obj, key)
    elif method == "RSA":
        return RSA_encrypt(obj, key)
    else:
        raise NotImplementedError("Sorry: Method:{} haven't been supported by LoopyCryptor.".format(method))


def decrypt(byte, method="AES", key=None):
    if method == "AES":
        return AES_decrypt(byte, key)
    elif method == "RSA":
        return RSA_decrypt(byte, key)
    else:
        raise NotImplementedError("Sorry: Method:{} haven't been supported by LoopyCryptor.".format(method))
