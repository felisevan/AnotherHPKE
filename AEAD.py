from abc import ABC, abstractmethod
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from constants import AEAD_IDS


class AbstractAead(ABC):
    """

    """

    @property
    @abstractmethod
    def id(self) -> AEAD_IDS:
        raise NotImplementedError

    @property
    @abstractmethod
    def Nk(self) -> int:
        raise NotImplementedError

    @property
    @abstractmethod
    def Nn(self) -> int:
        raise NotImplementedError

    @property
    @abstractmethod
    def Nt(self) -> int:
        raise NotImplementedError

    @property
    @abstractmethod
    def _algorithm(self) -> Callable:
        raise NotImplementedError

    def seal(self, key, nonce, aad, pt) -> bytes:
        """
        
        """

        cipher: AESGCM | ChaCha20Poly1305 = self._algorithm(key)
        return cipher.encrypt(nonce=nonce, data=pt, associated_data=aad)

    def open(self, key, nonce, aad, ct) -> bytes:
        """
        
        """
        cipher: AESGCM | ChaCha20Poly1305 = self._algorithm(key)
        return cipher.decrypt(nonce=nonce, data=ct, associated_data=aad)


class AeadAes256Gcm(AbstractAead):
    """
    
    """

    @property
    def id(self) -> AEAD_IDS:
        return AEAD_IDS.AES_256_GCM

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
    """
    
    """

    @property
    def id(self) -> AEAD_IDS:
        return AEAD_IDS.AES_128_GCM

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
    """
    
    """

    @property
    def id(self) -> AEAD_IDS:
        return AEAD_IDS.ChaCha20Poly1305

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
    """

    """

    @property
    def id(self) -> AEAD_IDS:
        return AEAD_IDS.Export_only

    @property
    def Nk(self) -> int:
        raise NotImplementedError

    @property
    def Nn(self) -> int:
        raise NotImplementedError

    @property
    def Nt(self) -> int:
        raise NotImplementedError

    @property
    def _algorithm(self) -> Callable:
        raise NotImplementedError

    def seal(self, key, nonce, aad, pt) -> bytes:
        raise NotImplementedError

    def open(self, key, nonce, aad, ct) -> bytes:
        raise NotImplementedError
