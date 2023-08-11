from enum import IntEnum, auto


class ModeIds(IntEnum):
    """
    MODE  identifiers' values
    """
    MODE_BASE = 0x00,
    MODE_PSK = 0x01
    MODE_AUTH = 0x02
    MODE_AUTH_PSK = 0x03


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
    HKDF_SHA256 = 0x0001
    HKDF_SHA384 = 0x0002
    HKDF_SHA512 = 0x0003


class AeadIds(IntEnum):
    """
    AEAD  identifiers' values
    """
    RESERVED = 0x0000
    AES_128_GCM = 0x0001
    AES_256_GCM = 0x0002
    ChaCha20Poly1305 = 0x0003
    Export_only = 0xFFFF


class RoleIds(IntEnum):
    """
    Role  identifiers' values
    This is NOT a part of standard, just for convenient.
    FYI, auto() starts from 1.
    """
    SENDER = auto()
    RECIPIENT = auto()
    EXPORTER = auto()