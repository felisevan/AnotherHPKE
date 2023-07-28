from abc import ABC, abstractmethod
from utilities import xor_bytes
from utilities import I2OSP
from KDF import AbstractHkdf
from AEAD import AbstractAead

class AbtractContext(ABC):
    """
    
    """

    def __init__(self, kdf: AbstractHkdf, aead : AbstractAead, exporter_secret: bytes, basenonce: bytes):
        self._kdf = kdf
        self._key = exporter_secret
        self._seq = 0
        self._aead = aead
        self._basenonce = basenonce

    def seal(self, aad, pt):
        """
        
        """

        cipher = self._aead.seal(self._key, self.compute_nonce(self._seq), aad, pt)
        self.increment_seq()
        return cipher
        
    def open(self, aad, ct):
        """
        
        """


        cipher = self._aead.open(self._key, self.compute_nonce(self._seq), aad, ct)
        self.increment_seq()
        return cipher

        
    def export(self, exporter_content, L):
        """
         
        """

        return self._kdf.labeled_expand(self._key, b"sec", exporter_content, L)
    
    def compute_nonce(self, seq) -> bytes:
        """
        
        """

        seq_bytes = I2OSP(seq, self._aead.Nn)
        return xor_bytes(self._basenonce, seq_bytes)
    
    def increment_seq(self):
        """
        
        """
        if self._seq >= (1 << (8 * self._aead.Nn)) - 1:
            raise MessageLimitReachedError
        self._seq += 1



class ContextExportOnly(AbtractContext):
    """
    
    """

    def __init__(self, kdf: AbstractHkdf, exporter_secret: bytes):
        """
        
        """

        self._kdf = kdf
        self._key = exporter_secret

    def seal(self):
        raise NotImplementedError("Invalid in export-only")
    
    def open(self):
        raise NotImplementedError("Invalid in export-only")
        



class ContextSender(AbtractContext):
    """
    
    """

    # def __init__(self, kdf: AbstractHkdf, aead: AbstractAead, exporter_secret: bytes, basenonce: bytes):
    #     super().__init__(kdf, aead, exporter_secret, basenonce)

    def open(self):
        raise NotImplementedError("Invalid in export-only")



class ContextRecipient(AbtractContext):
    """
    
    """

    def seal(self):
        raise NotImplementedError("Invalid in export-only")