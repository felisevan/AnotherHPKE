from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.hashes import HashAlgorithm, SHA256, SHA384, SHA512

from constants import KDF_IDS
from utilities import concat, I2OSP


class AbstractHkdf(ABC):
    """
    Abstract class of KDF with defining  methods.
    """

    @property
    @abstractmethod
    def id(self) -> KDF_IDS:
        """
        The KDF id.
        :rtype: object
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def _hash(self) -> HashAlgorithm:
        """
        The underlying hash method.
        :rtype: object
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def Nh(self) -> int:
        """
        The output size of the extract() methods in bytes.
        :rtype: object
        """

        raise NotImplementedError

    def _extract(self, salt: bytes, ikm: bytes) -> bytes:
        """
        Extract a pseudorandom key of fixed length Nh bytes from input keying material ikm and an optional byte string salt
        :param salt:
        :param ikm:
        :return:
        :rtype: object
        """
        ctx = hmac.HMAC(salt, self._hash)
        ctx.update(ikm)
        return ctx.finalize()

    def _expand(self, prk: bytes, info: bytes, L: int) -> bytes:
        """
        Expand a pseudorandom key prk using optional string info into L bytes of output keying material
        :param prk:
        :param info:
        :param L:
        :return:
        :rtype: object
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
        method extract with labeled ikm(keying material)
        :param salt:
        :param label:
        :param ikm:
        :param suite_id:
        :return:
        :rtype: object
        """

        labeled_ikm = concat(b"HPKE-v1", suite_id, label, ikm)
        return self._extract(
            salt=salt,
            ikm=labeled_ikm,
        )

    def labeled_expand(self, prk: bytes, label: bytes, info: bytes, L: int, suite_id: bytes) -> bytes:
        """
        method expand with labeled info(optional string)
        :param prk:
        :param label:
        :param info:
        :param L:
        :param suite_id:
        :return:
        :rtype: object
        """

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
    def id(self) -> KDF_IDS:
        """

        :rtype: object
        """
        return KDF_IDS.HKDF_SHA256

    @property
    def _hash(self) -> HashAlgorithm:
        """

        :rtype: object
        """
        return SHA256()

    @property
    def Nh(self) -> int:
        """

        :rtype: object
        """
        return 32


class HkdfSHA384(AbstractHkdf):
    """
    HKDF_SHA384
    """

    @property
    def id(self) -> KDF_IDS:
        """

        :rtype: object
        """
        return KDF_IDS.HKDF_SHA384

    @property
    def _hash(self) -> HashAlgorithm:
        """

        :rtype: object
        """
        return SHA384()

    @property
    def Nh(self) -> int:
        """

        :rtype: object
        """
        return 48


class HkdfSHA512(AbstractHkdf):
    """
    HKDF_SHA512
    """

    @property
    def id(self) -> KDF_IDS:
        """

        :rtype: object
        """
        return KDF_IDS.HKDF_SHA512

    @property
    def _hash(self) -> HashAlgorithm:
        """

        :rtype: object
        """
        return SHA512()

    @property
    def Nh(self) -> int:
        """

        :rtype: object
        """
        return 64


class KdfFactory:
    @classmethod
    def new(cls, kdf_id: KDF_IDS) -> HkdfSHA256 | HkdfSHA384 | HkdfSHA512:
        match kdf_id:
            case KDF_IDS.HKDF_SHA256:
                return HkdfSHA256()
            case KDF_IDS.HKDF_SHA384:
                return HkdfSHA384()
            case KDF_IDS.HKDF_SHA512:
                return HkdfSHA512()
            case _:
                raise NotImplementedError
