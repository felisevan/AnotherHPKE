from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.hashes import HashAlgorithm, SHA256, SHA384, SHA512

from .constants import KdfIds
from .utilities import concat, I2OSP


class AbstractHkdf(ABC):
    """
    Abstract class of KDF with defining methods.
    """

    @property
    @abstractmethod
    def id(self) -> KdfIds:
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

    def _extract(self, salt: bytes, ikm: bytes) -> bytes:
        """
        Extract a pseudorandom key of fixed length Nh bytes from input keying material ikm and an optional salt.
        :param salt: salt value
        :param ikm: input keying material
        :return: pseudorandom key with Nh bytes.
        """
        ctx = hmac.HMAC(salt, self._hash)
        ctx.update(ikm)
        return ctx.finalize()

    def _expand(self, prk: bytes, info: bytes, L: int) -> bytes:
        """
        Expand a pseudorandom key prk using optional string info into L bytes of output keying material
        :param prk: pseudorandom key
        :param info: optional string
        :param L: length
        :return: keying material with L bytes
        """
        assert L <= 255 * self._hash.digest_size

        t_n_minus_1 = b""
        n = 1
        data = b""

        while len(data) < L:
            ctx = hmac.HMAC(prk, self._hash)
            ctx.update(t_n_minus_1 + info + I2OSP(n, 1))
            t_n_minus_1 = ctx.finalize()
            data += t_n_minus_1
            n += 1
        return data[:L]

    def labeled_extract(self, salt: bytes, label: bytes, ikm: bytes, suite_id: bytes) -> bytes:
        """
        Extract a pseudorandom key of fixed length Nh bytes from input keying material ikm and an optional byte string
        salt but labeled with `label`
        :param salt: salt value
        :param label: specific label value
        :param ikm: input keying material
        :param suite_id: suite_id starts with "HPKE" and identify the entire cipher suite in use
        :return: extract result
        """

        labeled_ikm = concat(b"HPKE-v1", suite_id, label, ikm)
        return self._extract(
            salt=salt,
            ikm=labeled_ikm,
        )

    def labeled_expand(self, prk: bytes, label: bytes | None, info: bytes, L: int, suite_id: bytes) -> bytes:
        """
        Expand a pseudorandom key prk using optional string info into L bytes of output keying material,
        but labeled with `label`
        :param prk: pseudorandom key
        :param label: specific label value
        :param info: optional string
        :param L: length
        :param suite_id: suite_id starts with "HPKE" and identify the entire cipher suite in use
        :return: expand result
        """

        info = b"" if info is None else info

        labeled_info = concat(I2OSP(L, 2), b"HPKE-v1", suite_id, label, info)
        return self._expand(
            prk=prk,
            info=labeled_info,
            L=L,
        )


class HkdfSHA256(AbstractHkdf):
    """
    HKDF_SHA256
    """

    @property
    def id(self) -> KdfIds:
        return KdfIds.HKDF_SHA256

    @property
    def _hash(self) -> HashAlgorithm:
        return SHA256()

    @property
    def Nh(self) -> int:
        return 32


class HkdfSHA384(AbstractHkdf):
    """
    HKDF_SHA384
    """

    @property
    def id(self) -> KdfIds:
        return KdfIds.HKDF_SHA384

    @property
    def _hash(self) -> HashAlgorithm:
        return SHA384()

    @property
    def Nh(self) -> int:
        return 48


class HkdfSHA512(AbstractHkdf):
    """
    HKDF_SHA512
    """

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
    def new(cls, kdf_id: KdfIds) -> HkdfSHA256 | HkdfSHA384 | HkdfSHA512:
        """
        :param kdf_id: KDF id
        :return: return an instance of HkdfSHA256 or HkdfSHA384 or HkdfSHA512
        """
        match kdf_id:
            case KdfIds.HKDF_SHA256:
                return HkdfSHA256()
            case KdfIds.HKDF_SHA384:
                return HkdfSHA384()
            case KdfIds.HKDF_SHA512:
                return HkdfSHA512()
            case _:
                raise NotImplementedError
