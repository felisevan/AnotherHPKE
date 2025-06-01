from collections.abc import Callable
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .constants import AeadIds


# 2. Define the main AEAD Protocol
class AeadProtocol(Protocol):
    """
    Protocol defining the interface for an AEAD cipher.
    """

    @property
    def id(self) -> AeadIds:
        """The AEAD id."""
        ...

    @property
    def Nk(self) -> int:
        """The length in bytes of a key for this algorithm."""
        ...

    @property
    def Nn(self) -> int:
        """The length in bytes of a nonce for this algorithm."""
        ...

    @property
    def Nt(self) -> int:
        """The length in bytes of the authentication tag for this algorithm."""
        ...

    @property
    def _algorithm(self) -> Callable:
        """
        A callable that takes a key and returns an AEAD cipher instance.
        """
        ...

    def seal(self, key: bytes, nonce: bytes, aad: bytes | None, pt: bytes) -> bytes:
        """
        Encrypts plaintext `pt` and authenticates optional associated data `aad` using `key` and `nonce`.
        """
        ...

    def open(self, key: bytes, nonce: bytes, aad: bytes | None, ct: bytes) -> bytes:
        """
        Decrypts ciphertext `ct` and authenticates optional associated data `aad` using `key` and `nonce`.
        """
        ...


class AeadOperationMixin:
    """
    Mixin providing the seal and open operations for AEAD ciphers that conform to a part of the AeadProtocol.
    """

    def seal(
        self: AeadProtocol, key: bytes, nonce: bytes, aad: bytes | None, pt: bytes
    ) -> bytes:
        cipher_instance = self._algorithm(key)
        return cipher_instance.encrypt(nonce=nonce, data=pt, associated_data=aad)

    def open(
        self: AeadProtocol, key: bytes, nonce: bytes, aad: bytes | None, ct: bytes
    ) -> bytes:
        cipher_instance = self._algorithm(key)
        return cipher_instance.decrypt(nonce=nonce, data=ct, associated_data=aad)


class AeadAes256Gcm(AeadOperationMixin):
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
    def _algorithm(
        self,
    ) -> type[AESGCM]:
        return AESGCM


class AeadAes128Gcm(AeadOperationMixin):
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
    def _algorithm(self) -> type[AESGCM]:
        return AESGCM


class AeadChaCha20Poly1305(AeadOperationMixin):
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
    def _algorithm(
        self,
    ) -> type[ChaCha20Poly1305]:
        return ChaCha20Poly1305


class AeadExportOnly:
    @property
    def id(self) -> AeadIds:
        return AeadIds.Export_only

    @property
    def Nk(self) -> int:
        raise NotImplementedError("Export only: Nk not applicable")

    @property
    def Nn(self) -> int:
        raise NotImplementedError("Export only: Nn not applicable")

    @property
    def Nt(self) -> int:
        raise NotImplementedError("Export only: Nt not applicable")

    @property
    def _algorithm(
        self,
    ) -> Callable:
        raise NotImplementedError("Export only: _algorithm not applicable")

    def seal(self, key: bytes, nonce: bytes, aad: bytes | None, pt: bytes) -> bytes:
        raise NotImplementedError("Export only: seal operation not supported")

    def open(self, key: bytes, nonce: bytes, aad: bytes | None, ct: bytes) -> bytes:
        raise NotImplementedError("Export only: open operation not supported")


class AeadFactory:
    """
    AEAD factory class.
    """

    @classmethod
    def new(cls, aead_id: AeadIds) -> AeadProtocol:
        """
        Create an instance of corresponding AEAD.

        :param aead_id: AEAD id.
        :return: An instance conforming to AeadProtocol.
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
                raise NotImplementedError(
                    f"AEAD ID {aead_id} not implemented in factory."
                )
