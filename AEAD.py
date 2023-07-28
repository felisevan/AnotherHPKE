from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


class AbstractAead(ABC):
    """

    """

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
