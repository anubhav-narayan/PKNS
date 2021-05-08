'''
Object Serialization and Marshalling Sub-Layer
Ported from loopyCryptor
'''
__version__ = "0.2.0"
__author__ = "Anubhav Mattoo"
__email__ = "anubhavmattoo@outlook.com"
__license__ = "AGPLv3"
__status__ = "Public Beta"

import pickle5 as pickle


def to_bytes(obj, force_convert: bool = True) -> bytes:
    '''
    Serialize Object to Bytes
    '''
    if isinstance(obj, bytes) and not force_convert:
        return obj
    elif isinstance(obj, str) and not force_convert:
        return obj.encode('utf8')
    else:
        return pickle.dumps(obj)


def to_obj(data: bytes):
    return pickle.loads(data)


def byte_to_str(text: bytes, do_convert=True):
    '''
    Bytes to String
    '''
    if not do_convert:
        return text
    elif isinstance(text, str):
        return text
    elif isinstance(text, bytes):
        return text.decode('utf8')
    else:
        raise AttributeError(
            "Unable to convert {} to string".format(
                type(text)
            )
        )


def cut_bytes(data: bytes, fixed_length: int = 64) -> list:
    ''''
    Split the Data by fixed length
    '''

    byte_list = [data[fixed_length * i:fixed_length * i + fixed_length]
                 for i in range(len(data) // fixed_length)]
    if len(data) % fixed_length != 0:
        byte_list.append(data[-(len(data) % fixed_length):])
    return byte_list


def concat_byte_list(byte_list: list, add_break: bool = True) -> bytes:
    '''
    Concat Byte List optionally with Breaks
    '''
    res = b''
    for b in list(byte_list):
        res += (b + b'[BRK]') if add_break else b
    return res
