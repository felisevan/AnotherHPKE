from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.hashes import HashAlgorithm, SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from constants import KDF_IDS
from utilities import concat, I2OSP


class AbstractHkdf(ABC):
    """
    Abstract class of HKDF with declaring abstract methods.
    """

    @property
    @abstractmethod
    def id(self) -> KDF_IDS:
        """
        The KDF id.
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def _hash(self) -> HashAlgorithm:
        """
        The underlying hash function.
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def Nh(self) -> int:
        """
        The output size of the extract() methods in bytes.
        """

        raise NotImplementedError

    # def _extract(self, salt: bytes, ikm: bytes, info: bytes = b"") -> bytes:
    #     """
    #     Extract a pseudorandom key of fixed length `Nh` bytes from input keying material `ikm`
    #     and an optional byte string `salt`.
    #     """
    #
    #     hkdf = HKDF(
    #         algorithm=self._hash,
    #         length=self.Nh,
    #         salt=salt,
    #     )
    #     return hkdf.derive(ikm)
    #
    # def _expand(self, prk: bytes, info: bytes, L: int) -> bytes:
    #     """
    #     Expand a pseudorandom key `prk` using optional string `info` into `L` bytes of output keying material.
    #     """
    #
    #     hkdf = HKDFExpand(
    #         algorithm=self._hash,
    #         length=L,
    #         info=info,
    #     )
    #     return hkdf.derive(prk)

    def _extract(self, salt: bytes, ikm: bytes) -> bytes:
        ctx = hmac.HMAC(salt, self._hash)
        ctx.update(ikm)
        return ctx.finalize()

    def _expand(self, prk: bytes, info: bytes, L: int) -> bytes:
        assert L <= 255 * self._hash.digest_size

        t_n_minus_1 = b""
        n = 1
        data = b""

        while len(data) < L:
            ctx = hmac.HMAC(prk, self._hash)
            ctx.update(t_n_minus_1 + info + n.to_bytes(1, byteorder="big"))
            t_n_minus_1 = ctx.finalize()
            data += t_n_minus_1
            n += 1
        return data[:L]

    def labeled_extract(self, salt: bytes, label: bytes, ikm: bytes, suite_id: bytes) -> bytes:
        """
        with labeled ikm(keying material)
        """

        labeled_ikm = concat(b"HPKE-v1", suite_id, label, ikm)
        return self._extract(
            salt=salt,
            ikm=labeled_ikm,
        )

    def labeled_expand(self, prk: bytes, label: bytes, info: bytes, L: int, suite_id: bytes) -> bytes:
        """
        with labeled info(optional string)
        """

        labeled_info = concat(I2OSP(L, 2), b"HPKE-v1", suite_id, label, info)
        return self._expand(
            prk=prk,
            info=labeled_info,
            L=L,
        )


class HkdfSHA256(AbstractHkdf):
    """

    """

    @property
    def id(self) -> KDF_IDS:
        return KDF_IDS.HKDF_SHA256

    @property
    def _hash(self) -> HashAlgorithm:
        return SHA256()

    @property
    def Nh(self) -> int:
        return 32


class HkdfSHA384(AbstractHkdf):
    """
    
    """

    @property
    def id(self) -> KDF_IDS:
        return KDF_IDS.HKDF_SHA384

    @property
    def _hash(self) -> HashAlgorithm:
        return SHA384()

    @property
    def Nh(self) -> int:
        return 48


class HkdfSHA512(AbstractHkdf):
    """
    
    """

    @property
    def id(self) -> KDF_IDS:
        return KDF_IDS.HKDF_SHA512

    @property
    def _hash(self) -> HashAlgorithm:
        return SHA512()

    @property
    def Nh(self) -> int:
        return 64
