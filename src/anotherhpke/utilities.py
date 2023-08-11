def concat(*args: bytes) -> bytes:
    """
    Concatenate a list of bytes to a bytes.

    :param args: A list of bytes.
    :return: The concatenated result.
    """
    return b"".join(args)


def I2OSP(n: int, w: int) -> bytes:
    """
    Convert non-negative integer n to a w-length, big-endian byte string.

    :param n: A non-negative integer.
    :param w: The expected result length.
    :return: The byte string result.
    """

    return int.to_bytes(n, length=w, byteorder="big")


def OS2IP(x: bytes) -> int:
    """
    Convert byte string x to a non-negative integer.

    :param x: A byte string in big-endian.
    :return: The integer result.
    """

    return int.from_bytes(x, byteorder="big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings.

    :param a: A byte string.
    :param b: A byte string.
    :return: The XORed result.
    :raise ValueError: When input lengths of two input variables mismatched, it raises.
    """
    if len(a) != len(b):
        raise ValueError("the length of two bytes must be same")
    return bytes((x ^ y for x, y in zip(a, b)))
