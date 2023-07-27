from abc import ABC, abstractmethod
from utilities import xor_bytes
from utilities import I2OSP
from ciphersuite import base_nonce
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class AbstractAead(ABC):
    """

    """

    @abstractmethod
    def Seal(self, aad, pt):
        raise NotImplementedError

    @abstractmethod
    def Open(self, aad, ct):
        raise NotImplementedError

    @abstractmethod
    def __next_nonce(ctx):
        raise NotImplementedError

        

        

class AeadMethods(AbstractAead):
    """
    
    """

    NK = 0
    NN = 0
    NT = 0
    algorithm = None

    def __init__(self, key, basenonce):
        """
        
        """

        self._key = key
        self._base__nonce = base_nonce      
        self._seq = 0
    
    def _next_nonce(self):
        """
        
        """

        nonce = xor_bytes(self._base__nonce,I2OSP(self._seq))
        self._seq += 1
        return nonce


    def Seal(self, aad, pt):
        """
        
        """

        aesgcm = self.algorithm(key = self._key)
        ct = aesgcm.encrypt(self._next_nonce(), data = pt, aad = aad)
        return ct
        

    def Open(self, aad, ct):
        """
        
        """
        aesgcm = self.algorithm(key = self._key)
        pt = aesgcm.decrypt(nonce=self._next_nonce(),data = ct, aad = aad)
        return pt        



class AeadAes256Gcm(AeadMethods):
    """
    
    """

    NK = 32
    NN = 12
    NT = 16
    algorithm = AESGCM



class AeadAes128Gcm(AeadMethods):
    """
    
    """

    NK = 16
    NN = 12
    NT = 16
    algorithm = AESGCM



class AeadChaCha20Poly1305_1(AeadMethods):
    """
    
    """

    NK = 32
    NN = 12
    NT = 16
    algorithm = ChaCha20Poly1305