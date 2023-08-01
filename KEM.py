from abc import ABC, abstractmethod
from typing import Type

from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, derive_private_key, SECP256R1, SECP384R1, \
    SECP521R1, EllipticCurvePublicKey, EllipticCurve
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes

from KDF import AbstractHkdf, HkdfSHA256, HkdfSHA384, HkdfSHA512
from constants import KEM_IDS
from utilities import concat, I2OSP, OS2IP


class AbstractKEM(ABC):
    @property
    @abstractmethod
    def id(self) -> KEM_IDS:
        raise NotImplementedError

    @property
    @abstractmethod
    def _KDF(self) -> AbstractHkdf:
        raise NotImplementedError

    @property
    @abstractmethod
    def _Nsecret(self) -> int:
        raise NotImplementedError

    @property
    @abstractmethod
    def _Nsk(self) -> int:
        raise NotImplementedError

    @property
    @abstractmethod
    def _Npk(self) -> int:
        raise NotImplementedError

    @property
    def _suite_id(self) -> bytes:
        return concat(b"KEM", I2OSP(self.id, 2))

    @abstractmethod
    def generate_key_pair(self) -> tuple[PrivateKeyTypes, PublicKeyTypes]:
        raise NotImplementedError

    @abstractmethod
    def derive_key_pair(self, ikm: bytes) -> tuple[PrivateKeyTypes, PublicKeyTypes]:
        raise NotImplementedError

    @abstractmethod
    def serialize_public_key(self, pkX: PublicKeyTypes) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def deserialize_public_key(self, pkXm: bytes) -> PublicKeyTypes:
        raise NotImplementedError

    @abstractmethod
    def serialize_private_key(self, pkX: PrivateKeyTypes) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def deserialize_private_key(self, pkXm: bytes) -> PrivateKeyTypes:
        raise NotImplementedError

    def extract_and_expand(self, dh: bytes, kem_context: bytes) -> bytes:
        eae_prk = self._KDF.labeled_extract(
            salt=b"",
            label=b"eae_prk",
            ikm=dh,
            suite_id=self._suite_id
        )
        shared_secret = self._KDF.labeled_expand(
            prk=eae_prk,
            label=b"shared_secret",
            info=kem_context,
            L=self._Nsecret,
            suite_id=self._suite_id
        )
        return shared_secret

    def encap(self, pkR: PublicKeyTypes, skE: bytes = None, pkE: bytes = None):
        if (not skE) and (not pkE):
            skE, pkE = self.generate_key_pair()
        else:
            skE = self.deserialize_private_key(skE)
            pkE = self.deserialize_public_key(pkE)
            print("WARNING: skE and pkE are override by input value instead of random generated")
            assert skE.public_key() == pkE
        dh = skE.exchange(pkR)
        enc = self.serialize_public_key(pkE)

        pkRm = self.serialize_public_key(pkR)
        kem_context = concat(enc, pkRm)

        shared_secret = self.extract_and_expand(dh, kem_context)
        return shared_secret, enc

    def decap(self, enc: bytes, skR: PrivateKeyTypes):
        pkE = self.deserialize_public_key(enc)
        print(skR)
        dh = skR.exchange(pkE)

        pkRm = self.serialize_public_key(skR.public_key())
        kem_context = concat(enc, pkRm)

        shared_secret = self.extract_and_expand(dh, kem_context)
        return shared_secret

    def auth_encap(self, pkR: PublicKeyTypes, skS: PrivateKeyTypes, skE: bytes = None, pkE: bytes = None):
        if (not skE) and (not pkE):
            skE, pkE = self.generate_key_pair()
        else:
            skE = self.deserialize_private_key(skE)
            pkE = self.deserialize_public_key(pkE)
            print("WARNING: skE and pkE are override by input value instead of random generated")
            assert skE.public_key() == pkE
        dh = concat(skE.exchange(pkR), skS.exchange(pkR))
        enc = self.serialize_public_key(pkE)

        pkRm = self.serialize_public_key(pkR)
        pkSm = self.serialize_public_key(skS.public_key())
        kem_context = concat(enc, pkRm, pkSm)

        shared_secret = self.extract_and_expand(dh, kem_context)
        return shared_secret, enc

    def auth_decap(self, enc: bytes, skR: PrivateKeyTypes, pkS: PublicKeyTypes):
        pkE = self.deserialize_public_key(enc)
        dh = concat(skR.exchange(pkE), skR.exchange(pkS))

        pkRm = self.serialize_public_key(skR.public_key())
        pkSm = self.serialize_public_key(pkS)
        kem_context = concat(enc, pkRm, pkSm)

        shared_secret = self.extract_and_expand(dh, kem_context)
        return shared_secret


class EcAbstractKem(AbstractKEM):

    @property
    @abstractmethod
    def _curve(self) -> Type[EllipticCurve]:
        raise NotImplementedError

    @property
    @abstractmethod
    def _order(self) -> int:
        raise NotImplementedError

    @property
    @abstractmethod
    def _bitmask(self) -> int:
        raise NotImplementedError

    def generate_key_pair(self) -> tuple[PrivateKeyTypes, PublicKeyTypes]:
        private_key = generate_private_key(self._curve())
        public_key = private_key.public_key()
        return private_key, public_key

    def derive_key_pair(self, ikm: bytes) -> tuple[PrivateKeyTypes, PublicKeyTypes]:
        if len(ikm) < self._Nsk:
            raise ValueError("ikm doesn't have sufficient length")
        dkp_prk = self._KDF.labeled_extract(
            salt=b"",
            label=b"dkp_prk",
            ikm=ikm,
            suite_id=self._suite_id
        )
        sk = 0
        counter = 0
        while sk == 0 or sk >= self._order:
            if counter > 255:
                raise RuntimeError("You are too lucky to meet a good private key")
            _bytes = bytearray(self._KDF.labeled_expand(
                prk=dkp_prk,
                label=b"candidate",
                info=I2OSP(0, 1),
                L=self._Nsk,
                suite_id=self._suite_id
            ))
            _bytes[0] = _bytes[0] & self._bitmask
            sk = OS2IP(_bytes)
            counter = counter + 1
        sk = self.deserialize_private_key(I2OSP(sk, self._Nsk))
        return sk, sk.public_key()

    def serialize_public_key(self, pkX: PublicKeyTypes) -> bytes:
        return pkX.public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint
        )

    def deserialize_public_key(self, pkXm: bytes) -> PublicKeyTypes:
        if len(pkXm) != self._Npk:
            raise ValueError("Mismatched public key length")

        return EllipticCurvePublicKey.from_encoded_point(
            curve=self._curve(),
            data=pkXm
        )

    def serialize_private_key(self, pkX: PrivateKeyTypes) -> bytes:
        return I2OSP(pkX.private_numbers().private_value, self._Nsk)

    def deserialize_private_key(self, pkXm: bytes) -> PrivateKeyTypes:
        if OS2IP(pkXm) % self._order == 0:
            raise ValueError("the private key to be deserialized is insecure")
        return derive_private_key(OS2IP(pkXm), self._curve())


class DhKemP256HkdfSha256(EcAbstractKem):

    @property
    def _curve(self) -> Type[EllipticCurve]:
        return SECP256R1

    @property
    def _order(self) -> int:
        return 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

    @property
    def _bitmask(self) -> int:
        return 0xff

    @property
    def id(self) -> KEM_IDS:
        return KEM_IDS.DHKEM_P_256_HKDF_SHA256

    @property
    def _KDF(self) -> AbstractHkdf:
        return HkdfSHA256()

    @property
    def _Nsecret(self) -> int:
        return 32

    @property
    def _Nsk(self) -> int:
        return 32

    @property
    def _Npk(self) -> int:
        return 65


class DhKemP384HkdfSha384(EcAbstractKem):

    @property
    def _curve(self) -> Type[EllipticCurve]:
        return SECP384R1

    @property
    def _order(self) -> int:
        return 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973

    @property
    def _bitmask(self) -> int:
        return 0xff

    @property
    def id(self) -> KEM_IDS:
        return KEM_IDS.DHKEM_P_384_HKDF_SHA384

    @property
    def _KDF(self) -> AbstractHkdf:
        return HkdfSHA384()

    @property
    def _Nsecret(self) -> int:
        return 48

    @property
    def _Nsk(self) -> int:
        return 48

    @property
    def _Npk(self) -> int:
        return 97


class DhKemP521HkdfSha512(EcAbstractKem):

    @property
    def _curve(self) -> Type[EllipticCurve]:
        return SECP521R1

    @property
    def _order(self) -> int:
        return 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409

    @property
    def _bitmask(self) -> int:
        return 0x01

    @property
    def id(self) -> KEM_IDS:
        return KEM_IDS.DHKEM_P_521_HKDF_SHA512

    @property
    def _KDF(self) -> AbstractHkdf:
        return HkdfSHA512()

    @property
    def _Nsecret(self) -> int:
        return 64

    @property
    def _Nsk(self) -> int:
        return 66

    @property
    def _Npk(self) -> int:
        return 133


class XEcAbstractKem(AbstractKEM):

    @property
    @abstractmethod
    def _curve(self) -> PrivateKeyTypes:
        raise NotImplementedError

    def generate_key_pair(self) -> tuple[PrivateKeyTypes, PublicKeyTypes]:
        private_key = self._curve.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    def derive_key_pair(self, ikm: bytes) -> tuple[PrivateKeyTypes, PublicKeyTypes]:
        if len(ikm) < self._Nsk:
            raise ValueError("ikm doesn't have sufficient length")
        dkp_prk = self._KDF.labeled_extract(
            salt=b"",
            label=b"dkp_prk",
            ikm=ikm,
            suite_id=self._suite_id
        )
        sk = self._KDF.labeled_expand(
            prk=dkp_prk,
            label=b"sk",
            info=b"",
            L=self._Nsk,
            suite_id=self._suite_id
        )
        sk = self._curve.from_private_bytes(sk)
        return sk, sk.public_key()

    def serialize_public_key(self, pkX: PublicKeyTypes) -> bytes:
        return pkX.public_bytes_raw()

    def deserialize_public_key(self, pkXm: bytes) -> PublicKeyTypes:
        if len(pkXm) != self._Npk:
            raise ValueError("Mismatched public key length")

        if self._curve is X25519PrivateKey:
            public_curve = X25519PublicKey
        elif self._curve is X448PrivateKey:
            public_curve = X448PublicKey
        else:
            raise NotImplementedError("Curve not implemented")

        return public_curve.from_public_bytes(pkXm)

    def serialize_private_key(self, pkX: PrivateKeyTypes) -> bytes:
        return pkX.private_bytes_raw()

    def deserialize_private_key(self, pkXm: bytes) -> PrivateKeyTypes:
        return self._curve.from_private_bytes(pkXm)


class DhKemX25519HkdfSha256(XEcAbstractKem):
    @property
    def _curve(self) -> Type[X25519PrivateKey | X448PrivateKey]:
        return X25519PrivateKey

    @property
    def id(self) -> KEM_IDS:
        return KEM_IDS.DHKEM_X25519_HKDF_SHA256

    @property
    def _KDF(self) -> AbstractHkdf:
        return HkdfSHA256()

    @property
    def _Nsecret(self) -> int:
        return 32

    @property
    def _Nsk(self) -> int:
        return 32

    @property
    def _Npk(self) -> int:
        return 32


class DhKemX448HkdfSha512(XEcAbstractKem):
    @property
    def _curve(self) -> Type[X25519PrivateKey | X448PrivateKey]:
        return X448PrivateKey

    @property
    def id(self) -> KEM_IDS:
        return KEM_IDS.DHKEM_X448_HKDF_SHA512

    @property
    def _KDF(self) -> AbstractHkdf:
        return HkdfSHA512()

    @property
    def _Nsecret(self) -> int:
        return 64

    @property
    def _Nsk(self) -> int:
        return 56

    @property
    def _Npk(self) -> int:
        return 56


class KemFactory:
    @classmethod
    def new(cls, kem_id: KEM_IDS) -> DhKemP256HkdfSha256 | DhKemP384HkdfSha384 | DhKemP521HkdfSha512 | DhKemX25519HkdfSha256 | DhKemX448HkdfSha512:
        match kem_id:
            case KEM_IDS.DHKEM_P_256_HKDF_SHA256:
                return DhKemP256HkdfSha256()
            case KEM_IDS.DHKEM_P_384_HKDF_SHA384:
                return DhKemP384HkdfSha384()
            case KEM_IDS.DHKEM_P_521_HKDF_SHA512:
                return DhKemP521HkdfSha512()
            case KEM_IDS.DHKEM_X25519_HKDF_SHA256:
                return DhKemX25519HkdfSha256()
            case KEM_IDS.DHKEM_X448_HKDF_SHA512:
                return DhKemX448HkdfSha512()
            case _:
                raise NotImplementedError