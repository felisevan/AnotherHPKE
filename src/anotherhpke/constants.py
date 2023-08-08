from enum import IntEnum, auto


class ModeIds(IntEnum):
    """
    MODE  identifiers' values
    """
    MODE_BASE = 0x00,
    MODE_PSK = auto()
    MODE_AUTH = auto()
    MODE_AUTH_PSK = auto()


class KemIds(IntEnum):
    """
    KEM  identifiers' values
    """
    RESERVED = 0x0000
    DHKEM_P_256_HKDF_SHA256 = 0x0010,
    DHKEM_P_384_HKDF_SHA384 = 0x0011,
    DHKEM_P_521_HKDF_SHA512 = 0x0012,
    DHKEM_X25519_HKDF_SHA256 = 0x0020,
    DHKEM_X448_HKDF_SHA512 = 0x0021


class KdfIds(IntEnum):
    """
    KDF  identifiers' values
    """
    RESERVED = 0x0000
    HKDF_SHA256 = auto()
    HKDF_SHA384 = auto()
    HKDF_SHA512 = auto()


class AeadIds(IntEnum):
    """
    AEAD  identifiers' values
    """
    RESERVED = 0x0000
    AES_128_GCM = auto()
    AES_256_GCM = auto()
    ChaCha20Poly1305 = auto()
    Export_only = 0xFFFF
