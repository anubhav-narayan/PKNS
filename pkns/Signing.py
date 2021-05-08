'''
Object Transport Signing Meta Class
Ported from loopyCryptor
'''

from Crypto.Hash import (
    MD5,
    SHA3_256,
    SHA256
)

from .Serializer import *


class Sign():
    """
    Signing Meta-Class for Object Signing
    Signs MD5, SHA256, SHA3_256
    """

    def __init__(self):
        '''
        DO NOT Init a Class
        '''
        raise AttributeError("DO NOT INIT, CYKA!")

    @staticmethod
    def md5(obj, ret_hex=True):
        '''
        MD5 Signature of the Data
        '''
        md5_ = MD5.new()

        if isinstance(obj, list):
            for item in obj:
                md5_.update(to_bytes(item))
        elif len(to_bytes(obj)) > 500:
            return Sign.md5(cut_bytes(to_bytes(obj), cut_length=500),
                            ret_hex=ret_hex)
        else:
            md5_.update(to_bytes(obj))
        return md5_.hexdigest() if ret_hex else md5_

    @staticmethod
    def sha256(obj, ret_hex=True):
        '''
        SHA256 Signature of the Data
        '''
        sha_ = SHA256.new()

        if isinstance(obj, list):
            for item in obj:
                sha_.update(to_bytes(item))
        elif len(to_bytes(obj)) > 1024:
            return Sign.sha256(cut_bytes(to_bytes(obj), cut_length=1024),
                               ret_hex=ret_hex)
        else:
            sha_.update(to_bytes(obj))
        return sha_.hexdigest() if ret_hex else sha_

    @staticmethod
    def sha3_256(obj, ret_hex=True):
        '''
        SHA3_256 Signature of the Data
        '''
        sha_ = SHA3_256.new()

        if isinstance(obj, list):
            for item in obj:
                sha_.update(to_bytes(item))
        elif len(to_bytes(obj)) > 1024:
            return Sign.sha3_256(cut_bytes(to_bytes(obj), cut_length=1024),
                                 ret_hex=ret_hex)
        else:
            sha_.update(to_bytes(obj))
        return sha_.hexdigest() if ret_hex else sha_
