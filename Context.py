from utilities import xor_bytes
from utilities import I2OSP
from KDF import AbstractHkdf
from AEAD import AbstractAead


class MessageLimitReachedError(Exception):
    pass


class AbstractContext:
    """
    
    """

    def __init__(self, suite_id: bytes, kdf: AbstractHkdf, aead: AbstractAead, key: bytes, base_nonce: bytes, seq: int, exporter_secret: bytes):
        self._suite_id = suite_id
        self._kdf = kdf
        self._aead = aead
        self._key = key
        self._exporter_secret = exporter_secret
        self._seq = seq
        self._base_nonce = base_nonce

    def seal(self, aad, pt):
        """
        
        """

        cipher = self._aead.seal(self._key, self._compute_nonce(self._seq), aad, pt)
        self._increment_seq()
        return cipher

    def open(self, aad, ct):
        """
        
        """

        cipher = self._aead.open(self._key, self._compute_nonce(self._seq), aad, ct)
        self._increment_seq()
        return cipher

    def export(self, exporter_content, L):
        """
         
        """

        return self._kdf.labeled_expand(self._exporter_secret, b"sec", exporter_content, L, suite_id=self._suite_id)

    def _compute_nonce(self, seq) -> bytes:
        """
        
        """

        seq_bytes = I2OSP(seq, self._aead.Nn)
        return xor_bytes(self._base_nonce, seq_bytes)

    def _increment_seq(self):
        """
        
        """
        if self._seq >= (1 << (8 * self._aead.Nn)) - 1:
            raise MessageLimitReachedError
        self._seq += 1


class ContextExportOnly(AbstractContext):
    """
    
    """

    def __init__(self, suite_id: bytes, kdf: AbstractHkdf, exporter_secret: bytes):
        """

        """

        self._suite_id = suite_id
        self._kdf = kdf
        self._key = exporter_secret

    def seal(self, aad, pt):
        raise NotImplementedError("Invalid in export-only")

    def open(self, aad, ct):
        raise NotImplementedError("Invalid in export-only")


class ContextSender(AbstractContext):
    """
    
    """

    def open(self, aad, ct):
        raise NotImplementedError("Invalid in export-only")


class ContextRecipient(AbstractContext):
    """
    
    """

    def seal(self, aad, pt):
        raise NotImplementedError("Invalid in export-only")
