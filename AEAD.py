from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from constants import AEAD_IDS

class AbstractAead(ABC):
    """

    """

    @property
    @abstractmethod
    def id(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def Nk(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def Nn(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def Nt(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def _algorithm(self):
        raise NotImplementedError

    def seal(self, key, nonce, aad, pt):
        """
        
        """

        cipher = self._algorithm(key)
        return cipher.encrypt(nonce=nonce, data=pt, aad=aad)

    def open(self, key, nonce, aad, ct):
        """
        
        """
        cipher = self._algorithm(key)
        return cipher.decrypt(nonce=nonce, data=ct, aad=aad)


class AeadAes256Gcm(AbstractAead):
    """
    
    """

    @property
    def id(self):
        return AEAD_IDS.AES_256_GCM

    def Nk(self):
        return 32

    def Nn(self):
        return 12

    def Nt(self):
        return 16

    def _algorithm(self):
        return AESGCM


class AeadAes128Gcm(AbstractAead):
    """
    
    """

    @property
    def id(self):
        return AEAD_IDS.AES_128_GCM

    def Nk(self):
        return 16

    def Nn(self):
        return 12

    def Nt(self):
        return 16

    def _algorithm(self):
        return AESGCM


class AeadChaCha20Poly1305(AbstractAead):
    """
    
    """

    @property
    def id(self):
        return AEAD_IDS.ChaCha20Poly1305

    def Nk(self):
        return 32

    def Nn(self):
        return 12

    def Nt(self):
        return 16

    def _algorithm(self):
        return ChaCha20Poly1305


class AeadExportOnly(AbstractAead):
    """

    """

    @property
    def id(self):
        return AEAD_IDS.Export_only

    def Nk(self):
        raise NotImplementedError

    def Nn(self):
        raise NotImplementedError

    def Nt(self):
        raise NotImplementedError

    def seal(self, key, nonce, aad, pt):
        raise NotImplementedError

    def open(self, key, nonce, aad, ct):
        raise NotImplementedError
