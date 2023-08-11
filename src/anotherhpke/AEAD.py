from abc import ABC, abstractmethod
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .constants import AeadIds


class AbstractAead(ABC):
    """
    Abstract class of AEAD with declaring methods.
    """

    @property
    @abstractmethod
    def id(self) -> AeadIds:
        """
        The AEAD id.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def Nk(self) -> int:
        """
        The length in bytes of a key for this algorithm.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def Nn(self) -> int:
        """
        The length in bytes of a nonce for this algorithm.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def Nt(self) -> int:
        """
        The length in bytes of the authentication tag for this algorithm.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def _algorithm(self) -> Callable:
        """
        The underlying AEAD cipher.
        """
        raise NotImplementedError

    def seal(self, key: bytes, nonce: bytes, aad: bytes | None, pt: bytes) -> bytes:
        """
        Encrypts plaintext `pt` and authenticates optional associated data `aad` using `key` and `nonce`.

        :param key: A symmetric key.
        :param nonce: A nonce value.
        :param aad: Additional data that should be authenticated with the key, but does not need to be encrypted.
        :param pt: A Plaintext.
        :return: The ciphertext.
        """

        cipher = self._algorithm(key)
        return cipher.encrypt(nonce=nonce, data=pt, associated_data=aad)

    def open(self, key: bytes, nonce: bytes, aad: bytes | None, ct: bytes) -> bytes:
        """
        Decrypts ciphertext `ct` and authenticates optional associated data `aad` using `key` and `nonce`.

        :param key: A symmetric key.
        :param nonce: A nonce value.
        :param aad: Additional data to authenticate.
        :param ct: A Ciphertext.
        :return: The plaintext.
        """
        cipher = self._algorithm(key)
        return cipher.decrypt(nonce=nonce, data=ct, associated_data=aad)


class AeadAes256Gcm(AbstractAead):
    @property
    def id(self) -> AeadIds:
        return AeadIds.AES_256_GCM

    @property
    def Nk(self) -> int:
        return 32

    @property
    def Nn(self) -> int:
        return 12

    @property
    def Nt(self) -> int:
        return 16

    @property
    def _algorithm(self) -> Callable:
        return AESGCM


class AeadAes128Gcm(AbstractAead):
    @property
    def id(self) -> AeadIds:
        return AeadIds.AES_128_GCM

    @property
    def Nk(self) -> int:
        return 16

    @property
    def Nn(self) -> int:
        return 12

    @property
    def Nt(self) -> int:
        return 16

    @property
    def _algorithm(self) -> Callable:
        return AESGCM


class AeadChaCha20Poly1305(AbstractAead):
    @property
    def id(self) -> AeadIds:
        return AeadIds.ChaCha20Poly1305

    @property
    def Nk(self) -> int:
        return 32

    @property
    def Nn(self) -> int:
        return 12

    @property
    def Nt(self) -> int:
        return 16

    @property
    def _algorithm(self) -> Callable:
        return ChaCha20Poly1305


class AeadExportOnly(AbstractAead):
    @property
    def id(self) -> AeadIds:
        return AeadIds.Export_only

    @property
    def Nk(self) -> int:
        raise NotImplementedError("Export only")

    @property
    def Nn(self) -> int:
        raise NotImplementedError("Export only")

    @property
    def Nt(self) -> int:
        raise NotImplementedError("Export only")

    @property
    def _algorithm(self) -> Callable:
        raise NotImplementedError("Export only")

    def seal(self, key: None, nonce: None, aad: None, pt: None) -> None:
        raise NotImplementedError("Export only")

    def open(self, key: None, nonce: None, aad: None, ct: None) -> None:
        raise NotImplementedError("Export only")


class AeadFactory:
    """
    AEAD factory class.
    """

    @classmethod
    def new(cls, aead_id: AeadIds) -> AeadAes128Gcm | AeadAes256Gcm | AeadChaCha20Poly1305 | AeadExportOnly:
        """
        Create an instance of corresponding AEAD.

        :param aead_id: AEAD id.
        :return: An instance of AEAD.
        """
        match aead_id:
            case AeadIds.AES_128_GCM:
                return AeadAes128Gcm()
            case AeadIds.AES_256_GCM:
                return AeadAes256Gcm()
            case AeadIds.ChaCha20Poly1305:
                return AeadChaCha20Poly1305()
            case AeadIds.Export_only:
                return AeadExportOnly()
            case _:
                raise NotImplementedError
