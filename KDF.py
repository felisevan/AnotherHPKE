from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from utilities import concat, I2OSP  # TODO import error


class AbstractHkdf(ABC):
    """
    Abstract class of Hkdf with declaring abstract methods
    This class defined parameter types and return types
    First layer of the 3-layers-inheritance relationship
    """

    @classmethod
    @abstractmethod
    def extract(cls, salt: bytes, ikm: bytes, info: bytes = b"") -> bytes:
        """
        Extract a pseudorandom key of fixed length bytes 
        from input keying material and an optional byte string
        """

        raise NotImplementedError

    @classmethod
    @abstractmethod
    def expand(cls, prk: bytes, L: int, info: bytes = b"") -> bytes:
        """
        Expand a pseudorandom key using optional string 
        into bytes of output keying material.
        """

        raise NotImplementedError

    @classmethod
    @abstractmethod
    def labeled_extract(cls, salt: bytes, ikm: bytes, label: bytes, suite_id: bytes) -> bytes:
        """
        with labeled ikm(keying material)
        """

        raise NotImplementedError

    @classmethod
    @abstractmethod
    def labeled_expand(cls, prk: bytes, label: bytes, info: bytes, L: int, suite_id: bytes) -> bytes:
        """
        with labeled info(optional string)
        """

        raise NotImplementedError


class HkdfApis(AbstractHkdf):
    """
    
    """

    @classmethod
    @property
    @abstractmethod
    def _hash(cls) -> any:
        raise NotImplementedError

    @classmethod
    @property
    @abstractmethod
    def _Nh(cls) -> any:
        raise NotImplementedError

    @classmethod
    def extract(cls, salt: bytes, ikm: bytes, info: bytes = b"") -> bytes:
        hkdf = HKDF(
            algorithm=cls._hash,
            length=cls._Nh,
            salt=salt,
            info=info,
        )
        key = hkdf.derive(ikm)
        return key

    @classmethod
    def expand(cls, prk: bytes, L: int, info: bytes = b"") -> bytes:
        hkdf = HKDFExpand(
            algorithm=cls._hash,
            length=L,
            info=info,
        )
        key = hkdf.derive(prk)
        return key

    @classmethod
    def labeled_extract(cls, salt: bytes, ikm: bytes, label: bytes, suite_id: bytes) -> bytes:
        labeled_ikm = concat(b"HPKE-v1", suite_id, label, ikm)
        return cls.extract(salt, labeled_ikm, b"")

    @classmethod
    def labeled_expand(cls, prk: bytes, label: bytes, info: bytes, L: int, suite_id: bytes) -> bytes:
        if L == 0:
            return b""
        labeled_info = concat(I2OSP(L, 2), b"HPKE-v1", suite_id, label, info)
        return cls.expand(prk, L, labeled_info)


class HkdfSHA256(HkdfApis):
    """

    """

    @classmethod
    @property
    def _hash(cls):
        return hashes.SHA256()

    @classmethod
    @property
    def _Nh(cls) -> int:
        return 32


class HkdfSHA384(HkdfApis):
    """
    
    """

    @classmethod
    @property
    def _hash(cls):
        return hashes.SHA384()

    @classmethod
    @property
    def _Nh(cls) -> int:
        return 48


class HkdfSHA512(HkdfApis):
    """
    
    """

    @classmethod
    @property
    def _hash(cls):
        return hashes.SHA512()

    @classmethod
    @property
    def _Nh(cls) -> int:
        return 64
