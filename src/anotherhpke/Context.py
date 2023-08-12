from .constants import ModeIds, RoleIds
from .utilities import concat, I2OSP, xor_bytes, OS2IP


class BaseContext:
    """
    Abstract class of KDF with defining methods.
    """

    def __init__(self, ciphersuite, key: bytes, base_nonce: bytes, exporter_secret: bytes):
        """
        :param suite_id: suite id value
        :param kdf: specific KDF type
        :param aead: specific AEAD type
        :param key: key called by AEAD
        :param base_nonce: base nonce value
        :param exporter_secret: the value returned from labeled_expand
        """
        self.ciphersuite = ciphersuite
        self._key = key
        self._exporter_secret = exporter_secret
        self._base_nonce = base_nonce
        # TODO: seq upper bound check is buggy
        self._seq_ = 0

    @property
    def _seq(self):
        return self._seq_

    @_seq.setter
    def _seq(self, value):
        if self._seq_ >= (1 << (8 * self.ciphersuite.aead.Nn)) - 1:
            raise RuntimeError("Message limit reached")
        self._seq_ = value

    def seal(self, pt: bytes, aad: bytes = b"") -> bytes:
        """
        encrypt a plaintext with associated data aad in sender's context
        :param aad: aad value
        :param pt: plaintext value
        :return: ciphertext
        """
        cipher = self.ciphersuite.aead.seal(self._key, self._compute_nonce(), aad, pt)
        self._seq += 1
        return cipher

    def open(self, ct: bytes, aad: bytes = b"") -> bytes:
        """
        decrypt a ciphertext ct with associated data aad in recipient's context
        :param aad: aad value
        :param ct: ciphertext value
        :return: plaintext
        """
        cipher = self.ciphersuite.aead.open(self._key, self._compute_nonce(), aad, ct)
        self._seq += 1
        return cipher

    def export(self, exporter_content: bytes, L: int) -> bytes:
        """
        HPKE interface exporting secrets
        :param exporter_content: value returned from labeled_expand
        :param L: length
        :return: secret
        """
        return self.ciphersuite.kdf.labeled_expand(self._exporter_secret, b"sec", exporter_content, L, suite_id=self.ciphersuite.id)

    def _compute_nonce(self) -> bytes:
        """
        compute next nonce
        :param seq: sequence value
        :return: next nonce
        """
        ret = xor_bytes(self._base_nonce, I2OSP(self._seq, self.ciphersuite.aead.Nn))
        return ret


class ContextExportOnly(BaseContext):
    """
    Export-only
    """

    def seal(self, pt, aad=b"") -> bytes:
        raise NotImplementedError("Invalid in export-only")

    def open(self, ct, aad=b"") -> bytes:
        raise NotImplementedError("Invalid in export-only")


class ContextSender(BaseContext):
    """
    sender's context
    """

    def open(self, ct, aad=b"") -> bytes:
        raise NotImplementedError("Invalid in sender")


class ContextRecipient(BaseContext):
    """
    recipient's context
    """

    def seal(self, pt, aad=b"") -> bytes:
        raise NotImplementedError("Invalid in recipient")


class ContextFactory:
    def __init__(self, ciphersuite, role_id: RoleIds):
        self._default_psk = b""
        self._default_psk_id = b""
        self.ciphersuite = ciphersuite
        self._role_id = role_id

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

    def key_schedule(self, mode: ModeIds, shared_secret: bytes, info: bytes | None, psk: bytes,
                     psk_id: bytes) -> BaseContext | ContextExportOnly:
        self._verify_psk_inputs(mode, psk, psk_id)

        info = b"" if info is None else info

        psk_id_hash = self.ciphersuite.kdf.labeled_extract(
            b"",
            b"psk_id_hash",
            psk_id,
            suite_id=self.ciphersuite.id
        )
        info_hash = self.ciphersuite.kdf.labeled_extract(
            b"",
            b"info_hash",
            info,
            suite_id=self.ciphersuite.id
        )
        key_schedule_context = concat(I2OSP(mode, 1), psk_id_hash, info_hash)

        secret = self.ciphersuite.kdf.labeled_extract(shared_secret, b"secret", psk, suite_id=self.ciphersuite.id)

        key = self.ciphersuite.kdf.labeled_expand(
            secret,
            b"key",
            key_schedule_context,
            self.ciphersuite.aead.Nk,
            suite_id=self.ciphersuite.id
        )
        base_nonce = self.ciphersuite.kdf.labeled_expand(
            secret,
            b"base_nonce",
            key_schedule_context,
            self.ciphersuite.aead.Nn,
            suite_id=self.ciphersuite.id
        )

        exporter_secret = self.ciphersuite.kdf.labeled_expand(
            secret,
            b"exp",
            key_schedule_context,
            self.ciphersuite.kdf.Nh,
            suite_id=self.ciphersuite.id
        )

        match self._role_id:
            case RoleIds.SENDER:
                return ContextSender(
                    ciphersuite=self.ciphersuite,
                    key=key,
                    base_nonce=base_nonce,
                    exporter_secret=exporter_secret
                )
            case RoleIds.RECIPIENT:
                return ContextRecipient(
                    ciphersuite=self.ciphersuite,
                    key=key,
                    base_nonce=base_nonce,
                    exporter_secret=exporter_secret
                )
            case RoleIds.EXPORTER:
                return ContextExportOnly(
                    ciphersuite=self.ciphersuite,
                    key=key,
                    base_nonce=base_nonce,
                    exporter_secret=exporter_secret
                )
            case _:
                raise NotImplementedError("A new role")