from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
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
        Extract a pseudorandom key of fixed length `Nh` bytes from `salt` and input keying material `ikm`.

        :param salt: A salt value.
        :param ikm: An input keying material.
        :return: The pseudorandom key with Nh bytes.
        """
        ctx = hmac.HMAC(salt, self._hash)
        ctx.update(ikm)
        return ctx.finalize()

    def _expand(self, prk: bytes, info: bytes, L: int) -> bytes:
        """
        Expand a pseudorandom key `prk` using `info` into `L` bytes of output keying material.

        :param prk: A pseudorandom key.
        :param info: Application specific context information.
        :param L: The expected output length.
        :return: The keying material with L bytes.
        """
        return HKDFExpand(self._hash, L, info).derive(prk)

    def labeled_extract(self, salt: bytes, label: bytes, ikm: bytes, suite_id: bytes) -> bytes:
        """
        Extract a pseudorandom key of fixed length `Nh` bytes from `salt` and input keying material `ikm`
         but labeled with `label`.

        :param salt: A salt value.
        :param label: A specific label value to indicate the caller context.
        :param ikm: An input keying material.
        :param suite_id: A byte string to indicate who the caller is.
        :return: The extract result.
        """

        labeled_ikm = concat(b"HPKE-v1", suite_id, label, ikm)
        return self._extract(
            salt=salt,
            ikm=labeled_ikm,
        )

    def labeled_expand(self, prk: bytes, label: bytes, info: bytes, L: int, suite_id: bytes) -> bytes:
        """
        Expand a pseudorandom key prk using optional string info into L bytes of output keying material
        but labeled with `label`.

        :param prk: A pseudorandom key.
        :param label: A specific label value to indicate the caller context.
        :param info: Application specific context information.
        :param L: The expected output length.
        :param suite_id: A byte string to indicate who the caller is.
        :return: The expand result.
        """

        labeled_info = concat(I2OSP(L, 2), b"HPKE-v1", suite_id, label, info)
        return self._expand(
            prk=prk,
            info=labeled_info,
            L=L,
        )


class HkdfSHA256(AbstractHkdf):
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
        Create an instance of corresponding HKDF.

        :param kdf_id: KDF id.
        :return: An instance of HKDF.
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
