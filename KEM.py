import struct
from abc import ABC, abstractmethod
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, derive_private_key, SECP256R1, SECP384R1, \
    SECP521R1, EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from KDF import HKDF_SHA256, HKDF_SHA384, HKDF_SHA512
from modes import KEM_IDS


class KEM(ABC):
    @abstractmethod
    def __init__(self):
        # make my editor happy
        self.__ID = None
        self.__KDF = None
        self.__Nsecret = None
        self.__CURVE = None

    @abstractmethod
    def generate_key_pair(self) -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey] | Tuple[
        X25519PrivateKey, X25519PublicKey] | Tuple[X448PrivateKey, X448PublicKey]:
        raise NotImplementedError

    @abstractmethod
    def derive_key_pair(self, ikm) -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey] | Tuple[
        X25519PrivateKey, X25519PublicKey] | Tuple[X448PrivateKey, X448PublicKey]:
        raise NotImplementedError

    @abstractmethod
    def serialize_public_key(self, pkX: EllipticCurvePublicKey | X25519PublicKey | X448PublicKey) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def deserialize_public_key(self, pkXm: bytes) -> EllipticCurvePublicKey | X25519PublicKey | X448PublicKey:
        raise NotImplementedError

    def extract_and_expand(self, dh: bytes, kem_context: bytes) -> bytes:
        suite_id = b"KEM" + struct.pack(">H", self.__ID)
        eae_prk = self.__KDF.LabeledExtract("", "eae_prk", dh)
        shared_secret = self.__KDF.labeled_expand(eae_prk, "shared_secret", kem_context, self.__Nsecret, suite_id)
        return shared_secret

    def encap(self, pkR: EllipticCurvePublicKey | X25519PublicKey | X448PublicKey):
        skE, pkE = self.generate_key_pair()
        dh = skE.exchange(pkR)
        enc = self.serialize_public_key(pkE)

        pkRm = self.serialize_public_key(pkR)
        kem_context = enc + pkRm

        shared_secret = self.extract_and_expand(dh, kem_context)
        return shared_secret, enc

    def decap(self, enc: bytes, skR: EllipticCurvePrivateKey | X25519PrivateKey | X448PrivateKey):
        pkE = self.deserialize_public_key(enc)
        dh = skR.exchange(pkE)

        pkRm = self.serialize_public_key(skR.public_key())
        kem_context = enc + pkRm

        shared_secret = self.extract_and_expand(dh, kem_context)
        return shared_secret

    def auth_encap(self, pkR: EllipticCurvePublicKey | X25519PublicKey | X448PublicKey,
                   skS: EllipticCurvePrivateKey | X25519PrivateKey | X448PrivateKey):
        skE, pkE = self.generate_key_pair()
        dh = skE.exchange(pkR) + skS.exchange(pkR)
        enc = self.serialize_public_key(pkE)

        pkRm = self.serialize_public_key(pkR)
        pkSm = self.serialize_public_key(skS.public_key())
        kem_context = enc + pkRm + pkSm

        shared_secret = self.extract_and_expand(dh, kem_context)
        return shared_secret, enc

    def auth_decap(self, enc: bytes, skR: EllipticCurvePrivateKey | X25519PrivateKey | X448PrivateKey,
                   pkS: EllipticCurvePrivateKey | X25519PrivateKey | X448PrivateKey):
        pkE = self.deserialize_public_key(enc)
        dh = skR.exchange(pkE) + skR.exchange(pkS)

        pkRm = self.serialize_public_key(skR.public_key())
        pkSm = self.serialize_public_key(pkS)
        kem_context = enc + pkRm + pkSm

        shared_secret = self.extract_and_expand(dh, kem_context)
        return shared_secret


class ECKem(KEM):
    @abstractmethod
    def __init__(self):
        # make my editor happy
        self.__ID = None
        self.__KDF = None
        self.__Nsecret = None
        self.__CURVE = None

    def generate_key_pair(self) -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
        private_key = generate_private_key(self.__CURVE)
        public_key = private_key.public_key()
        return private_key, public_key

    def derive_key_pair(self, ikm: int) -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
        private_key = derive_private_key(ikm, self.__CURVE)
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_public_key(self, pkX: EllipticCurvePublicKey) -> bytes:
        return pkX.public_bytes(
            encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
        )

    def deserialize_public_key(self, pkXm: bytes) -> EllipticCurvePublicKey:
        return EllipticCurvePublicKey.from_encoded_point(self.__CURVE, pkXm)


class DhKemP256HkdfSha256(ECKem):
    def __init__(self):
        self.__ID = KEM_IDS.DHKEM_P_256_HKDF_SHA256
        self.__KDF = HKDF_SHA256
        self.__CURVE = SECP256R1()


class DhKemP384HkdfSha384(ECKem):
    def __init__(self):
        self.__ID = KEM_IDS.DHKEM_P_384_HKDF_SHA384
        self.__KDF = HKDF_SHA384
        self.__CURVE = SECP384R1()


class DhKemP521HkdfSha512(ECKem):
    def __init__(self):
        self.__ID = KEM_IDS.DHKEM_P_521_HKDF_SHA512
        self.__KDF = HKDF_SHA512
        self.__CURVE = SECP521R1()


class XECKem(KEM):
    @abstractmethod
    def __init__(self):
        # make my editor happy
        self.__ID = None
        self.__KDF = None
        self.__Nsecret = None
        self.__CURVE = None
        self.__PRIVATE_CURVE = None
        self.__PUVLIC_CURVE = None

    def generate_key_pair(self) -> Tuple[X25519PrivateKey, X25519PublicKey] | Tuple[X448PrivateKey, X448PublicKey]:
        private_key = self.__PRIVATE_CURVE.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    def derive_key_pair(self, ikm: int) -> Tuple[X25519PrivateKey, X25519PublicKey] | Tuple[
        X448PrivateKey, X448PublicKey]:
        private_key = self.__PRIVATE_CURVE.from_private_bytes(ikm.to_bytes(32, 'big'))
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_public_key(self, pkX: X25519PublicKey | X448PublicKey) -> bytes:
        return pkX.public_bytes_raw()

    def deserialize_public_key(self, pkXm: bytes) -> X25519PublicKey | X448PublicKey:
        return self.__PUVLIC_CURVE.from_public_bytes(pkXm)


class DhKemX25519HkdfSha256(XECKem):
    def __init__(self):
        self.__ID = KEM_IDS.DHKEM_P_256_HKDF_SHA256
        self.__KDF = HKDF_SHA256
        self.__PRIVATE_CURVE = X25519PrivateKey
        self.__PUVLIC_CURVE = X25519PublicKey


class DhKemX448HkdfSha512(XECKem):
    def __init__(self):
        self.__ID = KEM_IDS.DHKEM_X448_HKDF_SHA512
        self.__KDF = HKDF_SHA512
        self.__PRIVATE_CURVE = X448PrivateKey
        self.__PUVLIC_CURVE = X448PublicKey
