from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.hashes import HashAlgorithm, SHA256, SHA384, SHA512

from constants import KDF_IDS
from utilities import concat, I2OSP


class AbstractHkdf(ABC):
    """
    Abstract class of KDF with defining methods.
    """

    @property
    @abstractmethod
    def id(self) -> KDF_IDS:
        """
        The KDF id.
        :return: KDF id
        :rtype: KDF_IDS
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def _hash(self) -> HashAlgorithm:
        """
        The underlying hash method.
        :return: specific hash method in use
        :rtype: HashAlgorithm
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def Nh(self) -> int:
        """
        The output size of the extract() methods in bytes.
        :return: length of input keying material in bytes
        :rtype: int
        """

        raise NotImplementedError

    def _extract(self, salt: bytes, ikm: bytes) -> bytes:
        """
        Extract a pseudorandom key of fixed length Nh bytes from input keying material ikm and an optional byte string salt
        :param salt: salt value
        :param ikm: input keying material
        :return: pseudorandom key with Nh bytes
        :rtype: bytes
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
        :rtype: bytes
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
        :param salt: salt value
        :param label: specific label value
        :param ikm: input keying material
        :param suite_id: suite_id starts with "HPKE" and identify the entire cipher suite in use
        :return: _extract method with labeled input keying material
        :rtype: bytes
        """

        labeled_ikm = concat(b"HPKE-v1", suite_id, label, ikm)
        return self._extract(
            salt=salt,
            ikm=labeled_ikm,
        )

    def labeled_expand(self, prk: bytes, label: bytes, info: bytes, L: int, suite_id: bytes) -> bytes:
        """
        method expand with labeled info(optional string)
        :param prk: pseudorandom key
        :param label: specific label value
        :param info: optional string
        :param L: length
        :param suite_id: suite_id starts with "HPKE" and identify the entire cipher suite in use
        :return: _expand method with labeled info
        :rtype: bytes
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
        :rtype: KDF_IDS
        """
        return KDF_IDS.HKDF_SHA256

    @property
    def _hash(self) -> HashAlgorithm:
        """
        :rtype: HashAlgorithm
        """
        return SHA256()

    @property
    def Nh(self) -> int:
        """
        :rtype: int
        """
        return 32


class HkdfSHA384(AbstractHkdf):
    """
    HKDF_SHA384
    """

    @property
    def id(self) -> KDF_IDS:
        """
        :rtype: KDF_IDS
        """
        return KDF_IDS.HKDF_SHA384

    @property
    def _hash(self) -> HashAlgorithm:
        """
        :rtype: HashAlgorithm
        """
        return SHA384()

    @property
    def Nh(self) -> int:
        """
        :rtype: int
        """
        return 48


class HkdfSHA512(AbstractHkdf):
    """
    HKDF_SHA512
    """

    @property
    def id(self) -> KDF_IDS:
        """
        :rtype: KDF_IDS
        """
        return KDF_IDS.HKDF_SHA512

    @property
    def _hash(self) -> HashAlgorithm:
        """
        :rtype: HashAlgorithm
        """
        return SHA512()

    @property
    def Nh(self) -> int:
        """
        :rtype: int
        """
        return 64


class KdfFactory:
    """
    KDF factory class
    """

    @classmethod
    def new(cls, kdf_id: KDF_IDS) -> HkdfSHA256 | HkdfSHA384 | HkdfSHA512:
        """
        :param kdf_id: KDF id
        :return: return an instance of HkdfSHA256 or HkdfSHA384 or HkdfSHA512
        :rtype: HkdfSHA256 | HkdfSHA384 | HkdfSHA512
        """
        match kdf_id:
            case KDF_IDS.HKDF_SHA256:
                return HkdfSHA256()
            case KDF_IDS.HKDF_SHA384:
                return HkdfSHA384()
            case KDF_IDS.HKDF_SHA512:
                return HkdfSHA512()
            case _:
                raise NotImplementedError
