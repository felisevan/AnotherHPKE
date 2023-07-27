import struct
from abc import ABC, abstractmethod
from typing import Type

from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, derive_private_key, SECP256R1, SECP384R1, \
    SECP521R1, EllipticCurvePublicKey, EllipticCurvePrivateKey, EllipticCurve
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from KDF import HkdfSHA256, HkdfSHA384, HkdfSHA512
from constants import KEM_IDS


class KEM(ABC):
    @property
    @abstractmethod
    def _ID(self) -> KEM_IDS:
        raise NotImplementedError

    @property
    @abstractmethod
    def _KDF(self) -> Type[HkdfSHA256 | HkdfSHA384 | HkdfSHA512]:
        raise NotImplementedError

    @property
    @abstractmethod
    def _Nsecret(self) -> int:
        raise NotImplementedError

    @property
    @abstractmethod
    def _CURVE(self) -> Type[EllipticCurve | X25519PrivateKey | X448PrivateKey]:
        raise NotImplementedError

    def generate_key_pair(self) -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey] | tuple[
        X25519PrivateKey, X25519PublicKey] | tuple[X448PrivateKey, X448PublicKey]:
        private_key = generate_private_key(self._CURVE())
        public_key = private_key.public_key()
        return private_key, public_key

    def derive_key_pair(self, ikm) -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey] | tuple[
        X25519PrivateKey, X25519PublicKey] | tuple[X448PrivateKey, X448PublicKey]:
        private_key = derive_private_key(ikm, self._CURVE())
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_public_key(self, pkX: EllipticCurvePublicKey | X25519PublicKey | X448PublicKey) -> bytes:
        return pkX.public_bytes(encoding=Encoding.X962, format=PublicFormat.UncompressedPoint)

    def deserialize_public_key(self, pkXm: bytes) -> EllipticCurvePublicKey | X25519PublicKey | X448PublicKey:
        return EllipticCurvePublicKey.from_encoded_point(self._CURVE(), pkXm)

    def extract_and_expand(self, dh: bytes, kem_context: bytes) -> bytes:
        suite_id = b"KEM" + struct.pack(">H", self._ID)
        eae_prk = self._KDF.labeled_expand("", "eae_prk", dh, suite_id)
        shared_secret = self._KDF.labeled_expand(eae_prk, b"shared_secret", kem_context, self._Nsecret, suite_id)
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
                   pkS: EllipticCurvePublicKey | X25519PublicKey | X448PublicKey):
        pkE = self.deserialize_public_key(enc)
        dh = skR.exchange(pkE) + skR.exchange(pkS)

        pkRm = self.serialize_public_key(skR.public_key())
        pkSm = self.serialize_public_key(pkS)
        kem_context = enc + pkRm + pkSm

        shared_secret = self.extract_and_expand(dh, kem_context)
        return shared_secret


class DhKemP256HkdfSha256(KEM):
    @property
    def _ID(self) -> KEM_IDS:
        return KEM_IDS.DHKEM_P_256_HKDF_SHA256

    @property
    def _KDF(self) -> Type[HkdfSHA256 | HkdfSHA384 | HkdfSHA512]:
        return HkdfSHA256

    @property
    def _Nsecret(self) -> int:
        return 32

    @property
    def _CURVE(self) -> Type[SECP256R1]:
        return SECP256R1


class DhKemP384HkdfSha384(KEM):
    @property
    def _ID(self) -> KEM_IDS:
        return KEM_IDS.DHKEM_P_384_HKDF_SHA384

    @property
    def _KDF(self) -> Type[HkdfSHA256 | HkdfSHA384 | HkdfSHA512]:
        return HkdfSHA384

    @property
    def _Nsecret(self) -> int:
        return 48

    @property
    def _CURVE(self) -> Type[SECP384R1]:
        return SECP384R1


class DhKemP521HkdfSha512(KEM):
    @property
    def _ID(self) -> KEM_IDS:
        return KEM_IDS.DHKEM_P_521_HKDF_SHA512

    @property
    def _KDF(self) -> Type[HkdfSHA256 | HkdfSHA384 | HkdfSHA512]:
        return HkdfSHA512

    @property
    def _Nsecret(self) -> int:
        return 64

    @property
    def _CURVE(self) -> Type[SECP521R1]:
        return SECP521R1


class XECKem(KEM):
    def generate_key_pair(self) -> tuple[X25519PrivateKey, X25519PublicKey] | tuple[X448PrivateKey, X448PublicKey]:
        private_key = self._CURVE.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    def derive_key_pair(self, ikm: int) -> tuple[X25519PrivateKey, X25519PublicKey] | tuple[
        X448PrivateKey, X448PublicKey]:
        private_key = self._CURVE.from_private_bytes(ikm.to_bytes(32, 'big'))
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_public_key(self, pkX: X25519PublicKey | X448PublicKey) -> bytes:
        return pkX.public_bytes_raw()

    def deserialize_public_key(self, pkXm: bytes) -> X25519PublicKey | X448PublicKey:
        if self._CURVE is X25519PrivateKey:
            public_curve = X25519PublicKey
        elif self._CURVE is X448PrivateKey:
            public_curve = X448PublicKey
        else:
            raise NotImplementedError

        return public_curve.from_public_bytes(pkXm)


class DhKemX25519HkdfSha256(XECKem):
    @property
    def _ID(self) -> KEM_IDS:
        return KEM_IDS.DHKEM_X25519_HKDF_SHA256

    @property
    def _KDF(self) -> Type[HkdfSHA256 | HkdfSHA384 | HkdfSHA512]:
        return HkdfSHA256

    @property
    def _Nsecret(self) -> int:
        return 32

    @property
    def _CURVE(self) -> Type[X448PrivateKey]:
        return X448PrivateKey


class DhKemX448HkdfSha512(XECKem):
    @property
    def _ID(self) -> KEM_IDS:
        return KEM_IDS.DHKEM_X448_HKDF_SHA512

    @property
    def _KDF(self) -> Type[HkdfSHA256 | HkdfSHA384 | HkdfSHA512]:
        return HkdfSHA512

    @property
    def _Nsecret(self) -> int:
        return 64

    @property
    def _CURVE(self) -> Type[X448PrivateKey]:
        return X448PrivateKey
