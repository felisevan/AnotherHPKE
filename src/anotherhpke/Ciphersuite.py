from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes, PrivateKeyTypes

from .Context import ContextFactory
from .KDF import KdfFactory
from .KEM import KemFactory
from .AEAD import AeadFactory
from .constants import KdfIds, KemIds, AeadIds, ModeIds, RoleIds
from .utilities import concat, I2OSP


class Ciphersuite:
    def __init__(self, kem_id: KemIds, kdf_id: KdfIds, aead_id: AeadIds):
        self.id = concat(
            b"HPKE",
            I2OSP(kem_id, 2),
            I2OSP(kdf_id, 2),
            I2OSP(aead_id, 2)
        )
        self.aead = AeadFactory.new(aead_id)
        self.kem = KemFactory.new(kem_id)
        self.kdf = KdfFactory.new(kdf_id)
        self._default_psk = b""
        self._default_psk_id = b""

    def SetupBaseS(self, pkR: PublicKeyTypes, info: bytes | None = None, skE: bytes = None, pkE: bytes = None):
        shared_secret, enc = self.kem.encap(pkR, skE, pkE)
        return enc, ContextFactory(self, RoleIds.SENDER).key_schedule(ModeIds.MODE_BASE, shared_secret, info,
                                             self._default_psk, self._default_psk_id)

    def SetupBaseR(self, enc: bytes, skR: PrivateKeyTypes, info: bytes | None = None):
        shared_secret = self.kem.decap(enc, skR)
        return ContextFactory(self, RoleIds.RECIPIENT).key_schedule(ModeIds.MODE_BASE, shared_secret, info,
                                           self._default_psk, self._default_psk_id)

    def SetupPSKS(self, pkR: PublicKeyTypes, psk: bytes, psk_id: bytes, info: bytes | None = None, skE: bytes = None,
                  pkE: bytes = None):
        if len(psk) < 32:
            raise ValueError("psk doesn't have sufficient length")
        shared_secret, enc = self.kem.encap(pkR, skE, pkE)
        return enc, ContextFactory(self, RoleIds.SENDER).key_schedule(ModeIds.MODE_PSK, shared_secret, info,
                                             psk, psk_id)

    def SetupPSKR(self, enc: bytes, skR: PrivateKeyTypes, psk: bytes, psk_id: bytes, info: bytes | None = None):
        if len(psk) < 32:
            raise ValueError("psk doesn't have sufficient length")
        shared_secret = self.kem.decap(enc, skR)
        return ContextFactory(self, RoleIds.RECIPIENT).key_schedule(ModeIds.MODE_PSK, shared_secret, info, psk, psk_id)

    def SetupAuthS(self, pkR: PublicKeyTypes, skS: PrivateKeyTypes, info: bytes | None = None, skE: bytes = None,
                   pkE: bytes = None):
        shared_secret, enc = self.kem.auth_encap(pkR, skS, skE, pkE)
        return enc, ContextFactory(self, RoleIds.SENDER).key_schedule(ModeIds.MODE_AUTH, shared_secret, info,
                                             self._default_psk, self._default_psk_id)

    def SetupAuthR(self, enc: bytes, skR: PrivateKeyTypes, pkS: PublicKeyTypes, info: bytes | None = None):
        shared_secret = self.kem.auth_decap(enc, skR, pkS)
        return ContextFactory(self, RoleIds.RECIPIENT).key_schedule(ModeIds.MODE_AUTH, shared_secret, info,
                                           self._default_psk, self._default_psk_id)

    def SetupAuthPSKS(self, pkR: PublicKeyTypes, skS: PrivateKeyTypes, psk: bytes, psk_id: bytes,
                      info: bytes | None = None, skE: bytes = None, pkE: bytes = None):
        if len(psk) < 32:
            raise ValueError("psk doesn't have sufficient length")
        shared_secret, enc = self.kem.auth_encap(pkR, skS, skE, pkE)
        return enc, ContextFactory(self, RoleIds.SENDER).key_schedule(ModeIds.MODE_AUTH_PSK, shared_secret, info,
                                             psk, psk_id)

    def SetupAuthPSKR(self, enc: bytes, pkS: PublicKeyTypes, skR: PrivateKeyTypes, psk: bytes, psk_id: bytes,
                      info: bytes | None = None):
        if len(psk) < 32:
            raise ValueError("psk doesn't have sufficient length")
        shared_secret = self.kem.auth_decap(enc, skR, pkS)
        return ContextFactory(self, RoleIds.RECIPIENT).key_schedule(ModeIds.MODE_AUTH_PSK, shared_secret, info,
                                           psk, psk_id)