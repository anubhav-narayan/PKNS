import pickle


def to_byte(obj, force_convert=True):
    """
    make sure `text` is bytes

    :raise AttributeError: Text is not processable
    """
    if isinstance(obj, bytes) and not force_convert:
        return obj
    elif isinstance(obj, str) and not force_convert:
        return obj.encode()
    else:
        return pickle.dumps(obj)


def to_obj(byte):
    return pickle.loads(byte)


def byte_to_str(text, do_convert=True):
    """
    make sure `text` is string if `do_convert`

    :raise AttributeError: Text is not processable
    """
    if not do_convert:
        return text
    elif isinstance(text, str):
        return text
    elif isinstance(text, bytes):
        return text.decode()
    else:
        raise AttributeError(
            "Unable to convert {} to string.Text should be string or bytes".format(
                type(text)
            )
        )


def cut_bytes(bytes, cut_length=64):
    """
    Split the bytes by fixed length

    :param bytes: bytes to be cut
    :param cut_length: cut length, default is 50
    """

    byte_list = [bytes[cut_length * i:cut_length * i + cut_length] for i in range(len(bytes) // cut_length)]
    if len(bytes) % cut_length != 0:
        byte_list.append(bytes[-(len(bytes) % cut_length):])
    return byte_list


def concat_byte_list(byte_list, add_break=True):
    """
    concat a byte list
    """
    res = b''
    for b in list(byte_list):
        res += (b + b'[BRK]') if add_break else b
    return res
