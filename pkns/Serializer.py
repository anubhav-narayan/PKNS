'''
JSON-based object serialization with optional compression.
Designed to work with db86 JSON storage and network transport.
'''
__version__ = "0.3.0"
__author__ = "Anubhav Mattoo"
__email__ = "anubhavmattoo@outlook.com"
__license__ = "AGPLv3"
__status__ = "Public Beta"

import base64
import json
import zlib
from typing import Any

COMPRESSED_PREFIX = b'PKNSZ'
COMPRESS_LEVEL = 6


def _normalize_for_json(obj: Any):
    if isinstance(obj, bytes):
        return {"__bytes__": base64.b64encode(obj).decode("ascii")}
    if isinstance(obj, tuple):
        return {"__tuple__": [_normalize_for_json(item) for item in obj]}
    if isinstance(obj, list):
        return [_normalize_for_json(item) for item in obj]
    if isinstance(obj, dict):
        return {key: _normalize_for_json(value) for key, value in obj.items()}
    return obj


def _json_hook(obj: dict):
    if "__bytes__" in obj and len(obj) == 1:
        return base64.b64decode(obj["__bytes__"].encode("ascii"))
    if "__tuple__" in obj and len(obj) == 1:
        return tuple(obj["__tuple__"])
    return obj


def to_bytes(obj: Any, force_convert: bool = True, compress: bool = True) -> bytes:
    '''
    Serialize Python object to bytes using JSON.

    If ``force_convert`` is False and the object is already a bytes or str,
    it will be returned as-is (or encoded from str).
    Otherwise the object is converted to JSON and optionally compressed.
    '''
    if isinstance(obj, bytes) and not force_convert:
        return obj
    if isinstance(obj, str) and not force_convert:
        return obj.encode("utf8")

    normalized = _normalize_for_json(obj)
    json_data = json.dumps(normalized, separators=(",", ":"), sort_keys=True).encode("utf8")
    if compress:
        return COMPRESSED_PREFIX + zlib.compress(json_data, COMPRESS_LEVEL)
    return json_data


def to_obj(data: bytes, decompress: bool = True):
    '''
    Deserialize bytes back to a Python object using JSON.
    '''
    if isinstance(data, str):
        data = data.encode("utf8")
    if decompress and data.startswith(COMPRESSED_PREFIX):
        data = zlib.decompress(data[len(COMPRESSED_PREFIX):])
    return json.loads(data.decode("utf8"), object_hook=_json_hook)


def byte_to_str(text: Any, do_convert=True):
    '''
    Bytes to String
    '''
    if not do_convert:
        return text
    if isinstance(text, str):
        return text
    if isinstance(text, bytes):
        return text.decode("utf8")
    raise AttributeError(f"Unable to convert {type(text)} to string")


def cut_bytes(data: bytes, fixed_length: int = 64) -> list:
    '''
    Split the data by fixed length.
    '''
    byte_list = [data[fixed_length * i:fixed_length * i + fixed_length]
                 for i in range(len(data) // fixed_length)]
    if len(data) % fixed_length != 0:
        byte_list.append(data[-(len(data) % fixed_length):])
    return byte_list
