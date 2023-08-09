from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes, PrivateKeyTypes

from .AEAD import AeadFactory, AbstractAead
from .KDF import KdfFactory, AbstractHkdf
from .KEM import KemFactory
from .constants import ModeIds, KemIds, KdfIds, AeadIds
from .utilities import concat, I2OSP, xor_bytes


class AbstractContext:
    """
    Abstract class of KDF with defining methods.
    """

    def __init__(self, suite_id: bytes, kdf: AbstractHkdf, aead: AbstractAead, key: bytes, base_nonce: bytes, seq: int,
                 exporter_secret: bytes):
        """
        :param suite_id: suite id value
        :param kdf: specific KDF type
        :param aead: specific AEAD type
        :param key: key called by AEAD
        :param base_nonce: base nonce value
        :param seq: sequence value
        :param exporter_secret: the value returned from labeled_expand
        """
        self._suite_id = suite_id
        self._kdf = kdf
        self._aead = aead
        self._key = key
        self._exporter_secret = exporter_secret
        self._seq = seq
        self._base_nonce = base_nonce

    def seal(self, pt: bytes, aad: bytes = b"") -> bytes:
        """
        encrypt a plaintext with associated data aad in sender's context
        :param aad: aad value
        :param pt: plaintext value
        :return: ciphertext
        """
        cipher = self._aead.seal(self._key, self._compute_nonce(self._seq), aad, pt)
        self._increment_seq()
        return cipher

    def open(self, ct: bytes, aad: bytes = b"") -> bytes:
        """
        decrypt a ciphertext ct with associated data aad in recipient's context
        :param aad: aad value
        :param ct: ciphertext value
        :return: plaintext
        """
        cipher = self._aead.open(self._key, self._compute_nonce(self._seq), aad, ct)
        self._increment_seq()
        return cipher

    def export(self, exporter_content: bytes, L: int) -> bytes:
        """
        HPKE interface exporting secrets
        :param exporter_content: value returned from labeled_expand
        :param L: length
        :return: secret
        """
        return self._kdf.labeled_expand(self._exporter_secret, b"sec", exporter_content, L, suite_id=self._suite_id)

    def _compute_nonce(self, seq: int) -> bytes:
        """
        compute next nonce
        :param seq: sequence value
        :return: next nonce
        """
        seq_bytes = I2OSP(seq, self._aead.Nn)
        return xor_bytes(self._base_nonce, seq_bytes)

    def _increment_seq(self) -> None:
        """
        increase sequence value after each execution
        """
        if self._seq >= (1 << (8 * self._aead.Nn)) - 1:
            raise RuntimeError("Message limit reached")
        self._seq += 1


class ContextExportOnly(AbstractContext):
    """
    Export-only
    """

    def __init__(self, suite_id: bytes, kdf: AbstractHkdf, exporter_secret: bytes):
        self._suite_id = suite_id
        self._kdf = kdf
        self._key = exporter_secret

    def seal(self, pt, aad=b"") -> bytes:
        raise NotImplementedError("Invalid in export-only")

    def open(self, ct, aad=b"") -> bytes:
        raise NotImplementedError("Invalid in export-only")


class ContextSender(AbstractContext):
    """
    sender's context
    """

    def open(self, ct, aad=b"") -> bytes:
        raise NotImplementedError("Invalid in sender")


class ContextRecipient(AbstractContext):
    """
    recipient's context
    """

    def seal(self, pt, aad=b"") -> bytes:
        raise NotImplementedError("Invalid in recipient")


class ContextFactory:
    def __init__(self, kem: KemIds, kdf: KdfIds, aead: AeadIds):
        self.suite_id = concat(
            b"HPKE",
            I2OSP(kem, 2),
            I2OSP(kdf, 2),
            I2OSP(aead, 2)
        )
        self._default_psk = b""
        self._default_psk_id = b""
        self.aead = AeadFactory.new(aead)
        self.kem = KemFactory.new(kem)
        self.kdf = KdfFactory.new(kdf)

    def _verify_psk_inputs(self, mode: ModeIds, psk: bytes, psk_id: bytes):
        """
        verify psk inputs

        :param mode: the specific mode
        :param psk: the pre-shared key to be tested.
        :param psk_id: the pre-shared key id to be tested.

        """
        got_psk = (psk != self._default_psk)
        got_psk_id = (psk_id != self._default_psk_id)
        if got_psk != got_psk_id:
            raise ValueError("Inconsistent PSK inputs")

        if got_psk and (mode in [ModeIds.MODE_BASE, ModeIds.MODE_AUTH]):
            raise ValueError("PSK input provided when not needed")
        if (not got_psk) and (mode in [ModeIds.MODE_PSK, ModeIds.MODE_AUTH_PSK]):
            raise ValueError("Missing required PSK input")

    def _key_schedule(self, mode: ModeIds, shared_secret: bytes, info: bytes | None, psk: bytes, psk_id: bytes,
                      role: str) -> AbstractContext:
        self._verify_psk_inputs(mode, psk, psk_id)

        info = b"" if info is None else info

        psk_id_hash = self.kdf.labeled_extract(b"", b"psk_id_hash", psk_id, suite_id=self.suite_id)
        info_hash = self.kdf.labeled_extract(b"", b"info_hash", info, suite_id=self.suite_id)
        key_schedule_context = concat(I2OSP(mode, 1), psk_id_hash, info_hash)

        secret = self.kdf.labeled_extract(shared_secret, b"secret", psk, suite_id=self.suite_id)

        key = self.kdf.labeled_expand(secret, b"key", key_schedule_context, self.aead.Nk, suite_id=self.suite_id)
        base_nonce = self.kdf.labeled_expand(secret, b"base_nonce", key_schedule_context, self.aead.Nn,
                                             suite_id=self.suite_id)
        exporter_secret = self.kdf.labeled_expand(secret, b"exp", key_schedule_context, self.kdf.Nh,
                                                  suite_id=self.suite_id)

        if role == "sender":
            return ContextSender(
                suite_id=self.suite_id,
                kdf=self.kdf,
                aead=self.aead,
                key=key,
                base_nonce=base_nonce,
                seq=0,
                exporter_secret=exporter_secret
            )
        elif role == "recipient":
            return ContextRecipient(
                suite_id=self.suite_id,
                kdf=self.kdf,
                aead=self.aead,
                key=key,
                base_nonce=base_nonce,
                seq=0,
                exporter_secret=exporter_secret
            )
        elif role == "exporter":
            return ContextExportOnly(
                suite_id=self.suite_id,
                kdf=self.kdf,
                exporter_secret=exporter_secret
            )
        else:
            raise NotImplementedError("A new role")

    def key_schedule_sender(self, mode: ModeIds, shared_secret: bytes, info: bytes | None, psk: bytes, psk_id: bytes):
        return self._key_schedule(mode, shared_secret, info, psk, psk_id, "sender")

    def key_schedule_recipient(self, mode: ModeIds, shared_secret: bytes, info: bytes | None, psk: bytes,
                               psk_id: bytes):
        return self._key_schedule(mode, shared_secret, info, psk, psk_id, "recipient")

    def key_schedule_exporter(self, mode: ModeIds, shared_secret: bytes, info: bytes | None, psk: bytes,
                              psk_id: bytes):
        return self._key_schedule(mode, shared_secret, info, psk, psk_id, "exporter")

    def SetupBaseS(self, pkR: PublicKeyTypes, info: bytes | None = None, skE: bytes = None, pkE: bytes = None):
        shared_secret, enc = self.kem.encap(pkR, skE, pkE)
        return enc, self.key_schedule_sender(ModeIds.MODE_BASE, shared_secret, info,
                                             self._default_psk, self._default_psk_id)

    def SetupBaseR(self, enc: bytes, skR: PrivateKeyTypes, info: bytes | None = None):
        shared_secret = self.kem.decap(enc, skR)
        return self.key_schedule_recipient(ModeIds.MODE_BASE, shared_secret, info,
                                           self._default_psk, self._default_psk_id)

    def SetupPSKS(self, pkR: PublicKeyTypes, psk: bytes, psk_id: bytes, info: bytes | None = None, skE: bytes = None,
                  pkE: bytes = None):
        if len(psk) < 32:
            raise ValueError("psk doesn't have sufficient length")
        shared_secret, enc = self.kem.encap(pkR, skE, pkE)
        return enc, self.key_schedule_sender(ModeIds.MODE_PSK, shared_secret, info,
                                             psk, psk_id)

    def SetupPSKR(self, enc: bytes, skR: PrivateKeyTypes, psk: bytes, psk_id: bytes, info: bytes | None = None):
        if len(psk) < 32:
            raise ValueError("psk doesn't have sufficient length")
        shared_secret = self.kem.decap(enc, skR)
        return self.key_schedule_recipient(ModeIds.MODE_PSK, shared_secret, info, psk, psk_id)

    def SetupAuthS(self, pkR: PublicKeyTypes, skS: PrivateKeyTypes, info: bytes | None = None, skE: bytes = None,
                   pkE: bytes = None):
        shared_secret, enc = self.kem.auth_encap(pkR, skS, skE, pkE)
        return enc, self.key_schedule_sender(ModeIds.MODE_AUTH, shared_secret, info,
                                             self._default_psk, self._default_psk_id)

    def SetupAuthR(self, enc: bytes, skR: PrivateKeyTypes, pkS: PublicKeyTypes, info: bytes | None = None):
        shared_secret = self.kem.auth_decap(enc, skR, pkS)
        return self.key_schedule_recipient(ModeIds.MODE_AUTH, shared_secret, info,
                                           self._default_psk, self._default_psk_id)

    def SetupAuthPSKS(self, pkR: PublicKeyTypes, skS: PrivateKeyTypes, psk: bytes, psk_id: bytes,
                      info: bytes | None = None, skE: bytes = None, pkE: bytes = None):
        if len(psk) < 32:
            raise ValueError("psk doesn't have sufficient length")
        shared_secret, enc = self.kem.auth_encap(pkR, skS, skE, pkE)
        return enc, self.key_schedule_sender(ModeIds.MODE_AUTH_PSK, shared_secret, info,
                                             psk, psk_id)

    def SetupAuthPSKR(self, enc: bytes, pkS: PublicKeyTypes, skR: PrivateKeyTypes, psk: bytes, psk_id: bytes,
                      info: bytes | None = None):
        if len(psk) < 32:
            raise ValueError("psk doesn't have sufficient length")
        shared_secret = self.kem.auth_decap(enc, skR, pkS)
        return self.key_schedule_recipient(ModeIds.MODE_AUTH_PSK, shared_secret, info,
                                           psk, psk_id)
