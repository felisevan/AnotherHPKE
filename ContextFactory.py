from utilities import concat, I2OSP
from constants import HPKE_MODES
from KDF import AbstractHkdf
from KEM import AbstractKEM
from AEAD import AbstractAead
from Context import ContextExportOnly, ContextSender, ContextRecipient


class ContextFactory:
    def __init__(self, kem: AbstractKEM, kdf: AbstractHkdf, aead: AbstractAead):
        self.suite_id = concat(
            b"HPKE",
            I2OSP(kem.id, 2),
            I2OSP(kdf.id, 2),
            I2OSP(aead.id, 2)
        )
        self.kem = kem
        self.kdf = kdf
        self.aead = aead

    def _verify_psk_inputs(self, mode, psk=b"", psk_id=b""):
        got_psk = (psk != b"")
        got_psk_id = (psk_id != b"")
        if got_psk != got_psk_id:
            raise Exception("Inconsistent PSK inputs")

        if got_psk and (mode in [HPKE_MODES.MODE_BASE, HPKE_MODES.MODE_AUTH]):
            raise Exception("PSK input provided when not needed")
        if (not got_psk) and (mode in [HPKE_MODES.MODE_PSK, HPKE_MODES.MODE_AUTH_PSK]):
            raise Exception("Missing required PSK input")

    def _key_schedule(self, mode, shared_secret, info, psk, psk_id, role):
        self._verify_psk_inputs(mode, psk, psk_id)

        psk_id_hash = self.kdf.labeled_extract(b"", b"psk_id_hash", psk_id, suite_id=self.suite_id)
        info_hash = self.kdf.labeled_extract(b"", b"info_hash", info, suite_id=self.suite_id)
        key_schedule_context = concat(mode, psk_id_hash, info_hash)

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
            raise NotImplementedError

    def key_schedule_sender(self, mode, shared_secret, info, psk, psk_id):
        return self._key_schedule(mode, shared_secret, info, psk, psk_id, "sender")

    def key_schedule_recipient(self, mode, shared_secret, info, psk, psk_id):
        return self._key_schedule(mode, shared_secret, info, psk, psk_id, "recipient")

    def key_schedule_exporter(self, mode, shared_secret, info, psk, psk_id):
        return self._key_schedule(mode, shared_secret, info, psk, psk_id, "exporter")