from typing import Protocol, TypeVar

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256K1,
    SECP256R1,
    SECP384R1,
    SECP521R1,
    EllipticCurve,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    derive_private_key,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .constants import KemIds
from .KDF import HkdfSHA256, HkdfSHA384, HkdfSHA512, KdfProtocol
from .types import (
    HPKEPrivateKeyTypes,
    HPKEPublicKeyTypes,
    HPKEXCurvePrivateKey,
    HPKEXCurvePublicKey,
)
from .utilities import I2OSP, OS2IP, concat

PublicKeyTypeVar = TypeVar("PublicKeyTypeVar", bound=HPKEPublicKeyTypes)
PrivateKeyTypeVar = TypeVar("PrivateKeyTypeVar", bound=HPKEPrivateKeyTypes)


class KemProtocol(Protocol[PublicKeyTypeVar, PrivateKeyTypeVar]):
    @property
    def id(self) -> KemIds: ...
    @property
    def _KDF(self) -> KdfProtocol: ...
    @property
    def _Nsecret(self) -> int: ...
    @property
    def _Nsk(self) -> int: ...
    @property
    def _Npk(self) -> int: ...
    @property
    def auth(self) -> bool: ...
    @property
    def _suite_id(self) -> bytes: ...

    def generate_key_pair(self) -> tuple[PrivateKeyTypeVar, PublicKeyTypeVar]: ...
    def derive_key_pair(
        self, ikm: bytes
    ) -> tuple[PrivateKeyTypeVar, PublicKeyTypeVar]: ...
    def serialize_public_key(self, pkX: PublicKeyTypeVar) -> bytes: ...
    def deserialize_public_key(self, pkXm: bytes) -> PublicKeyTypeVar: ...
    def serialize_private_key(self, skX: PrivateKeyTypeVar) -> bytes: ...
    def deserialize_private_key(self, skXm: bytes) -> PrivateKeyTypeVar: ...
    def _exchange(self, sk: PrivateKeyTypeVar, pk: PublicKeyTypeVar) -> bytes: ...

    def extract_and_expand(self, dh: bytes, kem_context: bytes) -> bytes: ...
    def encap(
        self,
        pkR: PublicKeyTypeVar,
        skE: PrivateKeyTypeVar | None = None,
        pkE: PublicKeyTypeVar | None = None,
    ) -> tuple[bytes, bytes]: ...
    def decap(self, enc: bytes, skR: PrivateKeyTypeVar) -> bytes: ...
    def auth_encap(
        self,
        pkR: PublicKeyTypeVar,
        skS: PrivateKeyTypeVar,
        skE: PrivateKeyTypeVar | None = None,
        pkE: PublicKeyTypeVar | None = None,
    ) -> tuple[bytes, bytes]: ...
    def auth_decap(
        self, enc: bytes, skR: PrivateKeyTypeVar, pkS: PublicKeyTypeVar
    ) -> bytes: ...


class KemOperationMixin:
    @property
    def _suite_id(self: KemProtocol) -> bytes:
        return concat(b"KEM", I2OSP(self.id.value, 2))

    def extract_and_expand(self: KemProtocol, dh: bytes, kem_context: bytes) -> bytes:
        eae_prk = self._KDF.labeled_extract(
            salt=b"", label=b"eae_prk", ikm=dh, suite_id=self._suite_id
        )
        shared_secret = self._KDF.labeled_expand(
            prk=eae_prk,
            label=b"shared_secret",
            info=kem_context,
            L=self._Nsecret,
            suite_id=self._suite_id,
        )
        return shared_secret

    def encap(
        self: KemProtocol,
        pkR: HPKEPublicKeyTypes,
        skE: HPKEPrivateKeyTypes | None = None,
        pkE: HPKEPublicKeyTypes | None = None,
    ) -> tuple[bytes, bytes]:
        if skE is None and pkE is None:
            skE, pkE = self.generate_key_pair()
        elif skE is not None and pkE is not None:
            print(
                "WARNING: skE and pkE are overridden by input value instead of random generated."
            )
            assert skE.public_key() == pkE
        else:
            raise ValueError("skE and pkE must both be provided or both be None.")

        dh = self._exchange(skE, pkR)
        enc = self.serialize_public_key(pkE)

        pkRm = self.serialize_public_key(pkR)
        kem_context = concat(enc, pkRm)

        shared_secret = self.extract_and_expand(dh, kem_context)
        return shared_secret, enc

    def decap(self: KemProtocol, enc: bytes, skR: HPKEPrivateKeyTypes) -> bytes:
        pkE = self.deserialize_public_key(enc)
        dh = self._exchange(skR, pkE)

        pkRm = self.serialize_public_key(skR.public_key())
        kem_context = concat(enc, pkRm)

        shared_secret = self.extract_and_expand(dh, kem_context)
        return shared_secret

    def auth_encap(
        self: KemProtocol,
        pkR: HPKEPublicKeyTypes,
        skS: HPKEPrivateKeyTypes,
        skE: HPKEPrivateKeyTypes | None = None,
        pkE: HPKEPublicKeyTypes | None = None,
    ) -> tuple[bytes, bytes]:
        if not self.auth:
            raise NotImplementedError(f"AuthEncap not supported by {self.id}")

        if skE is None and pkE is None:
            skE, pkE = self.generate_key_pair()
        elif skE is not None and pkE is not None:
            print(
                "WARNING: skE and pkE are overridden by input value instead of random generated."
            )
            assert skE.public_key() == pkE
        else:
            raise ValueError("skE and pkE must both be provided or both be None.")

        dh = concat(self._exchange(skE, pkR), self._exchange(skS, pkR))
        enc = self.serialize_public_key(pkE)

        pkRm = self.serialize_public_key(pkR)
        pkSm = self.serialize_public_key(skS.public_key())
        kem_context = concat(enc, pkRm, pkSm)

        shared_secret = self.extract_and_expand(dh, kem_context)
        return shared_secret, enc

    def auth_decap(
        self: KemProtocol, enc: bytes, skR: HPKEPrivateKeyTypes, pkS: HPKEPublicKeyTypes
    ) -> bytes:
        if not self.auth:
            raise NotImplementedError(f"AuthDecap not supported by {self.id}")

        pkE = self.deserialize_public_key(enc)
        dh = concat(self._exchange(skR, pkE), self._exchange(skR, pkS))

        pkRm = self.serialize_public_key(skR.public_key())
        pkSm = self.serialize_public_key(pkS)
        kem_context = concat(enc, pkRm, pkSm)

        shared_secret = self.extract_and_expand(dh, kem_context)
        return shared_secret


class EcKemPrimitivesProtocol(KemProtocol, Protocol):
    @property
    def _curve(self) -> type[EllipticCurve]: ...
    @property
    def _order(self) -> int: ...
    @property
    def _bitmask(self) -> int: ...

    def _exchange(
        self, sk: EllipticCurvePrivateKey, pk: EllipticCurvePublicKey
    ) -> bytes: ...
    def generate_key_pair(
        self,
    ) -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]: ...
    def derive_key_pair(
        self, ikm: bytes
    ) -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]: ...
    def serialize_public_key(self, pkX: EllipticCurvePublicKey) -> bytes: ...
    def deserialize_public_key(self, pkXm: bytes) -> EllipticCurvePublicKey: ...
    def serialize_private_key(self, skX: EllipticCurvePrivateKey) -> bytes: ...
    def deserialize_private_key(self, skXm: bytes) -> EllipticCurvePrivateKey: ...


class EcKemPrimitivesMixin:
    def _exchange(
        self: EcKemPrimitivesProtocol,
        sk: EllipticCurvePrivateKey,
        pk: EllipticCurvePublicKey,
    ) -> bytes:
        return sk.exchange(ECDH(), pk)

    def generate_key_pair(
        self: EcKemPrimitivesProtocol,
    ) -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
        private_key = generate_private_key(self._curve())
        public_key = private_key.public_key()
        return private_key, public_key

    def derive_key_pair(
        self: EcKemPrimitivesProtocol, ikm: bytes
    ) -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
        if len(ikm) < self._Nsk:
            raise ValueError("ikm doesn't have sufficient length")
        dkp_prk = self._KDF.labeled_extract(
            salt=b"", label=b"dkp_prk", ikm=ikm, suite_id=self._suite_id
        )
        sk_val = 0
        counter = 0
        while sk_val == 0 or sk_val >= self._order:
            if counter > 255:
                raise RuntimeError(
                    "Could not derive a valid private key after 256 attempts"
                )
            _bytes_val = bytearray(
                self._KDF.labeled_expand(
                    prk=dkp_prk,
                    label=b"candidate",
                    info=I2OSP(counter, 1),
                    L=self._Nsk,
                    suite_id=self._suite_id,
                )
            )
            _bytes_val[0] = _bytes_val[0] & self._bitmask
            sk_val = OS2IP(_bytes_val)
            counter += 1
        sk_obj = self.deserialize_private_key(I2OSP(sk_val, self._Nsk))
        return sk_obj, sk_obj.public_key()

    def serialize_public_key(
        self: EcKemPrimitivesProtocol, pkX: EllipticCurvePublicKey
    ) -> bytes:
        return pkX.public_bytes(
            encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
        )

    def deserialize_public_key(
        self: EcKemPrimitivesProtocol, pkXm: bytes
    ) -> EllipticCurvePublicKey:
        if len(pkXm) != self._Npk:
            raise ValueError(
                f"Mismatched public key length. Expected {self._Npk}, got {len(pkXm)}"
            )
        return EllipticCurvePublicKey.from_encoded_point(curve=self._curve(), data=pkXm)

    def serialize_private_key(
        self: EcKemPrimitivesProtocol, skX: EllipticCurvePrivateKey
    ) -> bytes:
        return I2OSP(skX.private_numbers().private_value, self._Nsk)

    def deserialize_private_key(
        self: EcKemPrimitivesProtocol, skXm: bytes
    ) -> EllipticCurvePrivateKey:
        if OS2IP(skXm) % self._order == 0:
            raise ValueError(
                "The private key to be deserialized is insecure (value is 0 or multiple of order)"
            )
        return derive_private_key(OS2IP(skXm), self._curve())


class XEcKemPrimitivesProtocol(KemProtocol, Protocol):
    @property
    def _curve_cls(
        self,
    ) -> type[HPKEXCurvePrivateKey]: ...

    def _exchange(self, sk: HPKEXCurvePrivateKey, pk: HPKEXCurvePublicKey) -> bytes: ...
    def generate_key_pair(self) -> tuple[HPKEXCurvePrivateKey, HPKEXCurvePublicKey]: ...
    def derive_key_pair(
        self, ikm: bytes
    ) -> tuple[HPKEXCurvePrivateKey, HPKEXCurvePublicKey]: ...
    def serialize_public_key(self, pkX: HPKEXCurvePublicKey) -> bytes: ...
    def deserialize_public_key(self, pkXm: bytes) -> HPKEXCurvePublicKey: ...
    def serialize_private_key(self, skX: HPKEXCurvePrivateKey) -> bytes: ...
    def deserialize_private_key(self, skXm: bytes) -> HPKEXCurvePrivateKey: ...


class XEcKemPrimitivesMixin:
    def _exchange(
        self: XEcKemPrimitivesProtocol,
        sk: HPKEXCurvePrivateKey,
        pk: HPKEXCurvePublicKey,
    ) -> bytes:
        if isinstance(sk, X25519PrivateKey) and isinstance(pk, X25519PublicKey):
            return sk.exchange(pk)
        elif isinstance(sk, X448PrivateKey) and isinstance(pk, X448PublicKey):
            return sk.exchange(pk)
        else:
            raise ValueError("Mismatched key type.")

    def generate_key_pair(
        self: XEcKemPrimitivesProtocol,
    ) -> tuple[HPKEXCurvePrivateKey, HPKEXCurvePublicKey]:
        private_key = self._curve_cls.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    def derive_key_pair(
        self: XEcKemPrimitivesProtocol, ikm: bytes
    ) -> tuple[HPKEXCurvePrivateKey, HPKEXCurvePublicKey]:
        if len(ikm) < self._Nsk:
            raise ValueError("ikm doesn't have sufficient length")
        dkp_prk = self._KDF.labeled_extract(
            salt=b"", label=b"dkp_prk", ikm=ikm, suite_id=self._suite_id
        )
        sk_bytes = self._KDF.labeled_expand(
            prk=dkp_prk, label=b"sk", info=b"", L=self._Nsk, suite_id=self._suite_id
        )
        sk_obj = self.deserialize_private_key(sk_bytes)
        return sk_obj, sk_obj.public_key()

    def serialize_public_key(
        self: XEcKemPrimitivesProtocol, pkX: HPKEXCurvePublicKey
    ) -> bytes:
        return pkX.public_bytes_raw()

    def deserialize_public_key(
        self: XEcKemPrimitivesProtocol, pkXm: bytes
    ) -> HPKEXCurvePublicKey:
        if len(pkXm) != self._Npk:
            raise ValueError(
                f"Mismatched public key length. Expected {self._Npk}, got {len(pkXm)}"
            )

        if self._curve_cls is X25519PrivateKey:
            public_curve_cls: type[HPKEXCurvePublicKey] = X25519PublicKey
        elif self._curve_cls is X448PrivateKey:
            public_curve_cls = X448PublicKey
        else:
            raise TypeError(f"Unsupported X-curve private key class: {self._curve_cls}")
        return public_curve_cls.from_public_bytes(pkXm)

    def serialize_private_key(
        self: XEcKemPrimitivesProtocol, skX: HPKEXCurvePrivateKey
    ) -> bytes:
        return skX.private_bytes_raw()

    def deserialize_private_key(
        self: XEcKemPrimitivesProtocol, skXm: bytes
    ) -> HPKEXCurvePrivateKey:
        return self._curve_cls.from_private_bytes(skXm)


class DhKemP256HkdfSha256(KemOperationMixin, EcKemPrimitivesMixin):
    @property
    def _curve(self) -> type[EllipticCurve]:
        return SECP256R1

    @property
    def _order(self) -> int:
        return 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    @property
    def _bitmask(self) -> int:
        return 0xFF

    @property
    def id(self) -> KemIds:
        return KemIds.DHKEM_P_256_HKDF_SHA256

    @property
    def _KDF(self) -> KdfProtocol:
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

    @property
    def auth(self) -> bool:
        return True


class DhKemP384HkdfSha384(KemOperationMixin, EcKemPrimitivesMixin):
    @property
    def _curve(self) -> type[EllipticCurve]:
        return SECP384R1

    @property
    def _order(self) -> int:
        return 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973

    @property
    def _bitmask(self) -> int:
        return 0xFF

    @property
    def id(self) -> KemIds:
        return KemIds.DHKEM_P_384_HKDF_SHA384

    @property
    def _KDF(self) -> KdfProtocol:
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

    @property
    def auth(self) -> bool:
        return True


class DhKemP521HkdfSha512(KemOperationMixin, EcKemPrimitivesMixin):
    @property
    def _curve(self) -> type[EllipticCurve]:
        return SECP521R1

    @property
    def _order(self) -> int:
        return 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409

    @property
    def _bitmask(self) -> int:
        return 0x01

    @property
    def id(self) -> KemIds:
        return KemIds.DHKEM_P_521_HKDF_SHA512

    @property
    def _KDF(self) -> KdfProtocol:
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

    @property
    def auth(self) -> bool:
        return True


class DhKemSECP256K1HkdfSha256(KemOperationMixin, EcKemPrimitivesMixin):
    @property
    def _curve(self) -> type[EllipticCurve]:
        return SECP256K1

    @property
    def _order(self) -> int:
        return 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    @property
    def _bitmask(self) -> int:
        return 0xFF

    @property
    def id(self) -> KemIds:
        return KemIds.DHKEM_SECP256K1_HKDF_SHA256

    @property
    def _KDF(self) -> KdfProtocol:
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

    @property
    def auth(self) -> bool:
        return True


class DhKemX25519HkdfSha256(KemOperationMixin, XEcKemPrimitivesMixin):
    @property
    def _curve_cls(self) -> type[HPKEXCurvePrivateKey]:
        return X25519PrivateKey

    @property
    def id(self) -> KemIds:
        return KemIds.DHKEM_X25519_HKDF_SHA256

    @property
    def _KDF(self) -> KdfProtocol:
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

    @property
    def auth(self) -> bool:
        return True


class DhKemX448HkdfSha512(KemOperationMixin, XEcKemPrimitivesMixin):
    @property
    def _curve_cls(self) -> type[HPKEXCurvePrivateKey]:
        return X448PrivateKey

    @property
    def id(self) -> KemIds:
        return KemIds.DHKEM_X448_HKDF_SHA512

    @property
    def _KDF(self) -> KdfProtocol:
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

    @property
    def auth(self) -> bool:
        return True


class KemFactory:
    @classmethod
    def new(cls, kem_id: KemIds) -> KemProtocol:
        match kem_id:
            case KemIds.DHKEM_P_256_HKDF_SHA256:
                return DhKemP256HkdfSha256()
            case KemIds.DHKEM_P_384_HKDF_SHA384:
                return DhKemP384HkdfSha384()
            case KemIds.DHKEM_P_521_HKDF_SHA512:
                return DhKemP521HkdfSha512()
            case KemIds.DHKEM_SECP256K1_HKDF_SHA256:
                return DhKemSECP256K1HkdfSha256()
            case KemIds.DHKEM_X25519_HKDF_SHA256:
                return DhKemX25519HkdfSha256()
            case KemIds.DHKEM_X448_HKDF_SHA512:
                return DhKemX448HkdfSha512()
            case _:
                raise NotImplementedError(
                    f"KEM ID {kem_id} not implemented in factory."
                )
