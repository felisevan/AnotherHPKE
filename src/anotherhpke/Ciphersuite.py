from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes, PrivateKeyTypes

from .AEAD import AeadFactory
from .Context import ContextFactory
from .KDF import KdfFactory
from .KEM import KemFactory
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

    def SetupAuthPSKR(self, enc: bytes, skR: PrivateKeyTypes, pkS: PublicKeyTypes, psk: bytes, psk_id: bytes,
                      info: bytes | None = None):
        if len(psk) < 32:
            raise ValueError("psk doesn't have sufficient length")
        shared_secret = self.kem.auth_decap(enc, skR, pkS)
        return ContextFactory(self, RoleIds.RECIPIENT).key_schedule(ModeIds.MODE_AUTH_PSK, shared_secret, info,
                                                                    psk, psk_id)

    def SealBase(self, pkR: PublicKeyTypes, pt: bytes, info: bytes | None = None, aad: bytes = b"") -> tuple[bytes, bytes]:
        enc, ctx = self.SetupBaseS(pkR, info)
        ct = ctx.seal(pt, aad)
        return enc, ct

    def OpenBase(self, enc: bytes, skR: PrivateKeyTypes, ct: bytes, aad: bytes = b"", info: bytes | None = None) -> bytes:
        ctx = self.SetupBaseR(enc, skR, info)
        return ctx.open(ct, aad)

    def SendExportBase(self, pkR: PublicKeyTypes, exporter_context: bytes, L: int, info: bytes | None = None):
        enc, ctx = self.SetupBaseS(pkR, info)
        exported = ctx.export(exporter_context, L)
        return enc, exported

    def ReceiveExportBase(self, enc: bytes, skR: PrivateKeyTypes, exporter_context: bytes, L: int, info: bytes | None = None):
        ctx = self.SetupBaseR(enc, skR, info)
        return ctx.export(exporter_context, L)

    def SealPSK(self, pkR: PublicKeyTypes, psk: bytes, psk_id: bytes, pt: bytes, info: bytes | None = None, aad: bytes = b"") -> tuple[bytes, bytes]:
        enc, ctx = self.SetupPSKS(pkR, psk, psk_id, info)
        ct = ctx.seal(pt, aad)
        return enc, ct

    def OpenPSK(self, enc: bytes, skR: PrivateKeyTypes, psk: bytes, psk_id: bytes, ct: bytes, aad: bytes = b"", info: bytes | None = None) -> bytes:
        ctx = self.SetupPSKR(enc, skR, psk, psk_id, info)
        return ctx.open(ct, aad)

    def SendExportPSK(self, pkR: PublicKeyTypes, psk: bytes, psk_id: bytes, exporter_context: bytes, L: int, info: bytes | None = None):
        enc, ctx = self.SetupPSKS(pkR, psk, psk_id, info)
        exported = ctx.export(exporter_context, L)
        return enc, exported

    def ReceiveExportPSK(self, enc: bytes, skR: PrivateKeyTypes, psk: bytes, psk_id: bytes, exporter_context: bytes, L: int, info: bytes | None = None):
        ctx = self.SetupPSKR(enc, skR, psk, psk_id, info)
        return ctx.export(exporter_context, L)

    def SealAuth(self, pkR: PublicKeyTypes, skS: PrivateKeyTypes, pt: bytes, info: bytes | None = None, aad: bytes = b"") -> tuple[bytes, bytes]:
        enc, ctx = self.SetupAuthS(pkR, skS, info)
        ct = ctx.seal(pt, aad)
        return enc, ct

    def OpenAuth(self, enc: bytes, skR: PrivateKeyTypes, pkS: PublicKeyTypes, ct: bytes, aad: bytes = b"", info: bytes | None = None) -> bytes:
        ctx = self.SetupAuthR(enc, skR, pkS, info)
        return ctx.open(ct, aad)

    def SendExportAuth(self, pkR: PublicKeyTypes, skS: PrivateKeyTypes, exporter_context: bytes, L: int, info: bytes | None = None):
        enc, ctx = self.SetupAuthS(pkR, skS, info)
        exported = ctx.export(exporter_context, L)
        return enc, exported

    def ReceiveExportAuth(self, enc: bytes, skR: PrivateKeyTypes, pkS: PublicKeyTypes, exporter_context: bytes, L: int, info: bytes | None = None):
        ctx = self.SetupAuthR(enc, skR, pkS, info)
        return ctx.export(exporter_context, L)

    def SealAuthPSK(self, pkR: PublicKeyTypes, skS: PrivateKeyTypes, psk: bytes, psk_id: bytes, pt: bytes, info: bytes | None = None, aad: bytes = b"") -> tuple[bytes, bytes]:
        enc, ctx = self.SetupAuthPSKS(pkR, skS, psk, psk_id, info)
        ct = ctx.seal(pt, aad)
        return enc, ct

    def OpenAuthPSK(self, enc: bytes, skR: PrivateKeyTypes, pkS: PublicKeyTypes, psk: bytes, psk_id: bytes, ct: bytes, aad: bytes = b"", info: bytes | None = None) -> bytes:
        ctx = self.SetupAuthPSKR(enc, skR, pkS, psk, psk_id, info)
        return ctx.open(ct, aad)

    def SendExportAuthPSK(self, pkR: PublicKeyTypes, skS: PrivateKeyTypes, psk: bytes, psk_id: bytes, exporter_context: bytes, L: int, info: bytes | None = None):
        enc, ctx = self.SetupAuthPSKS(pkR, skS, psk, psk_id, info)
        exported = ctx.export(exporter_context, L)
        return enc, exported

    def ReceiveExportAuthPSK(self, enc: bytes, skR: PrivateKeyTypes, pkS: PublicKeyTypes, psk: bytes, psk_id: bytes, exporter_context: bytes, L: int, info: bytes | None = None):
        ctx = self.SetupAuthPSKR(enc, skR, pkS, psk, psk_id, info)
        return ctx.export(exporter_context, L)
