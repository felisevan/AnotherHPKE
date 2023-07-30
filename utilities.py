def concat(*args: bytes) -> bytes:
    return b"".join(args)


def I2OSP(n: int, w: int) -> bytes:
    """
    
    """

    return int.to_bytes(n, length=w, byteorder="big")


def OS2IP(x: bytes) -> int:
    """
    
    """

    return int.from_bytes(x, byteorder="big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    
    """
    if len(a) != len(b):
        raise ValueError("the length of two bytes must be same")
    return bytes((x ^ y for x, y in zip(a, b)))
