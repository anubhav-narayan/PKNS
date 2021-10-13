'''
Object Transport Signing Meta Class
Ported from loopyCryptor
'''

from Crypto.Hash import (
    MD5,
    SHA3_256,
    SHA256
)


class Sign():
    """
    Signing Meta-Class for Object Signing
    Signs MD5, SHA256, SHA3_256
    """

    def __init__(self):
        '''
        DO NOT Init this Class
        '''
        raise AttributeError("DO NOT INIT, CYKA!")

    @staticmethod
    def md5(obj: bytes, ret_hex=True) -> str or MD5:
        '''
        MD5 Signature of the Data
        '''
        md5_ = MD5.new()
        md5_.update(obj)
        return md5_.hexdigest() if ret_hex else md5_

    @staticmethod
    def sha256(obj: bytes, ret_hex=True) -> str or SHA256:
        '''
        SHA256 Signature of the Data
        '''
        sha_ = SHA256.new()
        sha_.update(obj)
        return sha_.hexdigest() if ret_hex else sha_

    @staticmethod
    def sha3_256(obj: bytes, ret_hex=True) -> str or SHA3_256:
        '''
        SHA3_256 Signature of the Data
        '''
        sha_ = SHA3_256.new()
        sha_.update(obj)
        return sha_.hexdigest() if ret_hex else sha_

    @staticmethod
    def sign(obj: bytes, sign_proto: callable):
        return sign_proto(obj)
