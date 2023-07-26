from enum import IntEnum


class HPKE_MODES(IntEnum):
    mode_base = 0x00, 
    mode_psk = 0x01,
    mode_auth =  0x02,
    mode_auth_psk = 0x03

class KEM_IDS(IntEnum):
    DHKEM_P_256_HKDF_SHA256 = 0x0010,
    DHKEM_P_384_HKDF_SHA384 = 0x0011,
    DHKEM_P_521_HKDF_SHA512 = 0x0012,
    DHKEM_X25519_HKDF_SHA256 = 0x0020,
    DHKEM_X448_HKDF_SHA512 = 0x0021

class KDF_IDS(IntEnum): 
    HKDF_SHA256 = 0x0001,
    HKDF_SHA384 = 0x0002,
    HKDF_SHA512 = 0x0003

class AEAD_IDS(IntEnum):
    AES_128_GCM = 0x0001,
    AES_256_GCM = 0x0002
    ChaCha20Poly1305 = 0x0003,
    Export_only = 0xFFFF