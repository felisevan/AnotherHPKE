def concat(*args: bytes) -> bytes:
    """
    Concatenate a list of bytes to a bytes.

    :param args: a list of bytes
    :return: bytes
    :rtype: bytes
    """
    return b"".join(args)


def I2OSP(n: int, w: int) -> bytes:
    """
    Convert non-negative integer n to a w-length, big-endian byte string
    :param n: non-negative integer
    :param w: length
    :return: byte string with w length
    :rtype: bytes
    """

    return int.to_bytes(n, length=w, byteorder="big")


def OS2IP(x: bytes) -> int:
    """
    Convert byte string x to a non-negative integer
    :param x: byte string in big-endian
    :return: integer
    :rtype: int
    """

    return int.from_bytes(x, byteorder="big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR of byte strings
    :param a: byte string a
    :param b: byte string b
    :return:  byte string after XOR computing
    :rtype: bytes
    :raise ValueError: When input lengths of two input variables mismatched, it raises.
    """
    if len(a) != len(b):
        raise ValueError("the length of two bytes must be same")
    return bytes((x ^ y for x, y in zip(a, b)))
