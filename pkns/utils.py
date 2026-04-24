"""
PKNS Utility Functions and Constants
"""

import socket
from copy import deepcopy


def dict_merge(a, b):
    """
    Recursively merge dictionary b into dictionary a.
    """
    if not isinstance(b, dict):
        return b
    result = deepcopy(a)
    for k, v in b.items():
        if k in result and isinstance(result[k], dict):
            result[k] = dict_merge(result[k], v)
        else:
            result[k] = deepcopy(v)
    return result


def get_constants(prefix):
    """
    Create a dictionary mapping socket module constants to their names.
    """
    return {
        getattr(socket, n): n
        for n in dir(socket)
        if n.startswith(prefix)
    }


# Socket constants
FAMILIES = get_constants('AF_')
PROTOCOLS = get_constants('IPPROTO_')
