from abc import ABC, abstractmethod
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from constants import AEAD_IDS


class AbstractAead(ABC):
    """
    Abstract class of AEAD with declaring  methods.
    """

    @property
    @abstractmethod
    def id(self) -> AEAD_IDS:
        """
        the AEAD id
        :rtype: AEAD_IDS
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def Nk(self) -> int:
        """
        The length in bytes of a key for this algorithm
        :rtype: int
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def Nn(self) -> int:
        """
        The length in bytes of a nonce for this algorithm
        :rtype: int
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def Nt(self) -> int:
        """
        The length in bytes of the authentication tag for this algorithm
        :rtype: int
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def _algorithm(self) -> Callable:
        """
        method gives the algorithm that is used
        :rtype: Callable
        """
        raise NotImplementedError

    def seal(self, key, nonce, aad, pt) -> bytes:
        """
        Encrypt and authenticate plaintext pt with associated data aad using symmetric key and nonce,
        yielding ciphertext and tag ct.
        This function can raise a MessageLimitReachedError upon failure
        :param key: symmetric key
        :param nonce: nonce value
        :param aad: associated data
        :param pt: plaintext
        :return: ciphertext
        :rtype: bytes
        """

        cipher: AESGCM | ChaCha20Poly1305 = self._algorithm(key)
        return cipher.encrypt(nonce=nonce, data=pt, associated_data=aad)

    def open(self, key, nonce, aad, ct) -> bytes:
        """
        Decrypt ciphertext and tag ct using associated data aad with symmetric key and nonce,
         returning plaintext message pt.
         This function can raise an OpenError or MessageLimitReachedError upon failure.
        :param key: symmetric key
        :param nonce: nonce value
        :param aad: associated data
        :param ct: plaintext
        :return: plaintext
        :rtype: bytes
        """
        cipher: AESGCM | ChaCha20Poly1305 = self._algorithm(key)
        return cipher.decrypt(nonce=nonce, data=ct, associated_data=aad)


class AeadAes256Gcm(AbstractAead):
    """
    AES-256-GCM
    """

    @property
    def id(self) -> AEAD_IDS:
        """
        :rtype: AEAD_IDS
        """
        return AEAD_IDS.AES_256_GCM

    @property
    def Nk(self) -> int:
        """
        :rtype: int
        """
        return 32

    @property
    def Nn(self) -> int:
        """
        :rtype: int
        """
        return 12

    @property
    def Nt(self) -> int:
        """
        :rtype: int
        """
        return 16

    @property
    def _algorithm(self) -> Callable:
        """
        :rtype: Callable
        """
        return AESGCM


class AeadAes128Gcm(AbstractAead):
    """
    AES-128-GCM
    """

    @property
    def id(self) -> AEAD_IDS:
        """
        :rtype: AEAD_IDS
        """
        return AEAD_IDS.AES_128_GCM

    @property
    def Nk(self) -> int:
        """
        :rtype: int
        """
        return 16

    @property
    def Nn(self) -> int:
        """
        :rtype: int
        """
        return 12

    @property
    def Nt(self) -> int:
        """
        :rtype: int
        """
        return 16

    @property
    def _algorithm(self) -> Callable:
        """
        :rtype: Callable
        """
        return AESGCM


class AeadChaCha20Poly1305(AbstractAead):
    """
    ChaCha20Poly1305
    """

    @property
    def id(self) -> AEAD_IDS:
        """

        :rtype: AEAD_IDS
        """
        return AEAD_IDS.ChaCha20Poly1305

    @property
    def Nk(self) -> int:
        """
        :rtype: int
        """
        return 32

    @property
    def Nn(self) -> int:
        """
        :rtype: int
        """
        return 12

    @property
    def Nt(self) -> int:
        """
        :rtype: int
        """
        return 16

    @property
    def _algorithm(self) -> Callable:
        """
        :rtype: Callable
        """
        return ChaCha20Poly1305


class AeadExportOnly(AbstractAead):
    """
    Export-only
    """

    @property
    def id(self) -> AEAD_IDS:
        """
        :rtype: AEAD_IDS
        """
        return AEAD_IDS.Export_only

    @property
    def Nk(self) -> int:
        """
        :rtype: int
        """
        raise NotImplementedError("Export only")

    @property
    def Nn(self) -> int:
        """
        :rtype: int
        """
        raise NotImplementedError("Export only")

    @property
    def Nt(self) -> int:
        """
        :rtype: int
        """
        raise NotImplementedError("Export only")

    @property
    def _algorithm(self) -> Callable:
        """
        :rtype: Callable
        """
        raise NotImplementedError("Export only")

    def seal(self, key, nonce, aad, pt) -> bytes:
        """
        :rtype: bytes
        """
        raise NotImplementedError("Export only")

    def open(self, key, nonce, aad, ct) -> bytes:
        """
        :rtype: bytes
        """
        raise NotImplementedError("Export only")


class AeadFactory:
    """
    AEAD factory class
    """

    @classmethod
    def new(cls, aead_id: AEAD_IDS) -> AeadAes128Gcm | AeadAes256Gcm | AeadChaCha20Poly1305 | AeadExportOnly:
        """
        return an instance of AeadAes128Gcm or AeadAes256Gcm or AeadChaCha20Poly1305 or AeadExportOnly
        :param aead_id: AEAD id
        :return: an instance
        :rtype: AeadAes128Gcm | AeadAes256Gcm | AeadChaCha20Poly1305 | AeadExportOnly
        """
        match aead_id:
            case AEAD_IDS.AES_128_GCM:
                return AeadAes128Gcm()
            case AEAD_IDS.AES_256_GCM:
                return AeadAes256Gcm()
            case AEAD_IDS.ChaCha20Poly1305:
                return AeadChaCha20Poly1305()
            case AEAD_IDS.Export_only:
                return AeadExportOnly()
            case _:
                raise NotImplementedError
