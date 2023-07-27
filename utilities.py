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

# def suite_id
