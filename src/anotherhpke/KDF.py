from typing import Protocol

from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512, HashAlgorithm
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from .constants import KdfIds
from .utilities import I2OSP, concat


class KdfProtocol(Protocol):
    """
    Protocol defining the interface for a Key Derivation Function (KDF),
    specifically an HKDF-like one.
    """

    @property
    def id(self) -> KdfIds:
        """The KDF id."""
        ...

    @property
    def _hash(self) -> HashAlgorithm:
        """The underlying hash function instance."""
        ...

    @property
    def Nh(self) -> int:
        """The output size of the extract() methods in bytes."""
        ...

    def _extract(self, salt: bytes, ikm: bytes) -> bytes:
        """
        Extract a pseudorandom key of fixed length `Nh` bytes from `salt` and input keying material `ikm`.
        """
        ...

    def _expand(self, prk: bytes, info: bytes, L: int) -> bytes:
        """
        Expand a pseudorandom key `prk` using `info` into `L` bytes of output keying material.
        """
        ...

    def labeled_extract(
        self, salt: bytes, label: bytes, ikm: bytes, suite_id: bytes
    ) -> bytes:
        """
        Extract a pseudorandom key but labeled.
        """
        ...

    def labeled_expand(
        self, prk: bytes, label: bytes, info: bytes, L: int, suite_id: bytes
    ) -> bytes:
        """
        Expand a pseudorandom key but labeled.
        """
        ...


class HkdfOperationMixin:
    """
    Mixin providing the common HKDF operations (_extract, _expand, labeled_extract, labeled_expand)
    for KDFs that conform to a part of the KdfProtocol (specifically, providing _hash).
    """

    def _extract(self: KdfProtocol, salt: bytes, ikm: bytes) -> bytes:
        ctx = hmac.HMAC(salt, self._hash)
        ctx.update(ikm)
        return ctx.finalize()

    def _expand(self: KdfProtocol, prk: bytes, info: bytes, L: int) -> bytes:
        return HKDFExpand(algorithm=self._hash, length=L, info=info).derive(prk)

    def labeled_extract(
        self: KdfProtocol, salt: bytes, label: bytes, ikm: bytes, suite_id: bytes
    ) -> bytes:
        labeled_ikm = concat(b"HPKE-v1", suite_id, label, ikm)
        return self._extract(
            salt=salt,
            ikm=labeled_ikm,
        )

    def labeled_expand(
        self: KdfProtocol,
        prk: bytes,
        label: bytes,
        info: bytes,
        L: int,
        suite_id: bytes,
    ) -> bytes:
        labeled_info = concat(I2OSP(L, 2), b"HPKE-v1", suite_id, label, info)
        return self._expand(
            prk=prk,
            info=labeled_info,
            L=L,
        )


class HkdfSHA256(HkdfOperationMixin):
    @property
    def id(self) -> KdfIds:
        return KdfIds.HKDF_SHA256

    @property
    def _hash(
        self,
    ) -> HashAlgorithm:
        return SHA256()

    @property
    def Nh(self) -> int:
        return 32


class HkdfSHA384(HkdfOperationMixin):
    @property
    def id(self) -> KdfIds:
        return KdfIds.HKDF_SHA384

    @property
    def _hash(self) -> HashAlgorithm:
        return SHA384()

    @property
    def Nh(self) -> int:
        return 48


class HkdfSHA512(HkdfOperationMixin):
    @property
    def id(self) -> KdfIds:
        return KdfIds.HKDF_SHA512

    @property
    def _hash(self) -> HashAlgorithm:
        return SHA512()

    @property
    def Nh(self) -> int:
        return 64


class KdfFactory:
    """
    KDF factory class
    """

    @classmethod
    def new(cls, kdf_id: KdfIds) -> KdfProtocol:
        """
        Create an instance of corresponding HKDF.

        :param kdf_id: KDF id.
        :return: An instance conforming to KdfProtocol.
        """
        match kdf_id:
            case KdfIds.HKDF_SHA256:
                return HkdfSHA256()
            case KdfIds.HKDF_SHA384:
                return HkdfSHA384()
            case KdfIds.HKDF_SHA512:
                return HkdfSHA512()
            case _:
                raise NotImplementedError(
                    f"KDF ID {kdf_id} not implemented in factory."
                )
