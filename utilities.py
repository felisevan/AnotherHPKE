def concat(*args: bytes) -> bytes:
    return b"".join(args)


def I2OSP(n: int, w: int) -> bytes:
    """
    
    """

    if n <= 0:
        raise ValueError("n must be non-negative")

    return int.to_bytes(n, length=w, byteorder="big", )


def OS2IP(x: bytes) -> int:
    """
    
    """

    return int.from_bytes(x, byteorder="big")


def xor_bytes(value1,value2):
    """
    
    """

    f = lambda a,b: bytes([x ^ y for x,y in zip(a,b)])
    return f(value1,value2)


# def suite_id