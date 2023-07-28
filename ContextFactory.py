from utilities import concat, I2OSP
from constants import MODE_IDS, KEM_IDS, KDF_IDS, AEAD_IDS
from KDF import HkdfSHA256, HkdfSHA384, HkdfSHA512
from KEM import DhKemP256HkdfSha256, DhKemP384HkdfSha384, DhKemP521HkdfSha512, DhKemX25519HkdfSha256, \
    DhKemX448HkdfSha512
from AEAD import AeadFactory
from Context import ContextExportOnly, ContextSender, ContextRecipient


class ContextFactory:
    def __init__(self, kem: KEM_IDS, kdf: KDF_IDS, aead: AEAD_IDS):
        self.suite_id = concat(
            b"HPKE",
            I2OSP(kem, 2),
            I2OSP(kdf, 2),
            I2OSP(aead, 2)
        )
        self._default_psk = b""
        self._default_psk_id = b""
        self.aead = AeadFactory.new(aead)
        match kem:
            case KEM_IDS.DHKEM_P_256_HKDF_SHA256:
                self.kem = DhKemP256HkdfSha256()
            case KEM_IDS.DHKEM_P_384_HKDF_SHA384:
                self.kem = DhKemP384HkdfSha384()
            case KEM_IDS.DHKEM_P_521_HKDF_SHA512:
                self.kem = DhKemP521HkdfSha512()
            case KEM_IDS.DHKEM_X25519_HKDF_SHA256:
                self.kem = DhKemX25519HkdfSha256()
            case KEM_IDS.DHKEM_X448_HKDF_SHA512:
                self.kem = DhKemX448HkdfSha512()
            case _:
                raise NotImplementedError
        match kdf:
            case KDF_IDS.HKDF_SHA256:
                self.kdf = HkdfSHA256()
            case KDF_IDS.HKDF_SHA384:
                self.kdf = HkdfSHA384()
            case KDF_IDS.HKDF_SHA512:
                self.kdf = HkdfSHA512()
            case _:
                raise NotImplementedError

    def _verify_psk_inputs(self, mode, psk=b"", psk_id=b""):
        got_psk = (self._default_psk != b"")
        got_psk_id = (self._default_psk_id != b"")
        if got_psk != got_psk_id:
            raise Exception("Inconsistent PSK inputs")

        if got_psk and (mode in [MODE_IDS.MODE_BASE, MODE_IDS.MODE_AUTH]):
            raise Exception("PSK input provided when not needed")
        if (not got_psk) and (mode in [MODE_IDS.MODE_PSK, MODE_IDS.MODE_AUTH_PSK]):
            raise Exception("Missing required PSK input")

    def _key_schedule(self, mode, shared_secret, info, psk, psk_id, role):
        # self._verify_psk_inputs(mode, psk, psk_id)
        # FIXME: this function is considered as broken.

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
            raise NotImplementedError

    def key_schedule_sender(self, mode, shared_secret, info, psk, psk_id):
        return self._key_schedule(mode, shared_secret, info, psk, psk_id, "sender")

    def key_schedule_recipient(self, mode, shared_secret, info, psk, psk_id):
        return self._key_schedule(mode, shared_secret, info, psk, psk_id, "recipient")

    def key_schedule_exporter(self, mode, shared_secret, info, psk, psk_id):
        return self._key_schedule(mode, shared_secret, info, psk, psk_id, "exporter")

    def SetupBaseS(self, pkR, info):
        shared_secret, enc = self.kem.encap(pkR)
        return enc, self.key_schedule_sender(MODE_IDS.MODE_BASE, shared_secret, info,
                                             self._default_psk, self._default_psk_id)

    def SetupBaseR(self, enc, skR, info):
        shared_secret = self.kem.decap(enc, skR)
        return self.key_schedule_recipient(MODE_IDS.MODE_BASE, shared_secret, info,
                                           self._default_psk, self._default_psk_id)

    def SetupPSKS(self, pkR, info, psk, psk_id):
        shared_secret, enc = self.kem.encap(pkR)
        return enc, self.key_schedule_sender(MODE_IDS.MODE_PSK, shared_secret, info,
                                             psk, psk_id)

    def SetupPSKR(self, enc, skR, info, psk, psk_id):
        shared_secret = self.kem.decap(enc, skR)
        return self.key_schedule_recipient(MODE_IDS.MODE_PSK, shared_secret, info, psk, psk_id)

    def SetupAuthS(self, pkR, info, skS):
        shared_secret, enc = self.kem.auth_encap(pkR, skS)
        return enc, self.key_schedule_sender(MODE_IDS.MODE_AUTH, shared_secret, info,
                                             self._default_psk, self._default_psk_id)

    def SetupAuthR(self, enc, skR, info, pkS):
        shared_secret = self.kem.auth_decap(enc, skR, pkS)
        return self.key_schedule_recipient(MODE_IDS.MODE_AUTH, shared_secret, info,
                                           self._default_psk, self._default_psk_id)

    def SetupAuthPSKS(self, pkR, info, psk, psk_id, skS):
        shared_secret, enc = self.kem.auth_encap(pkR, skS)
        return enc, self.key_schedule_sender(MODE_IDS.MODE_AUTH_PSK, shared_secret, info,
                                             psk, psk_id)

    def SetupAuthPSKR(self, enc, skR, info, psk, psk_id, pkS):
        shared_secret = self.kem.auth_decap(enc, skR, pkS)
        return self.key_schedule_recipient(MODE_IDS.MODE_AUTH_PSK, shared_secret, info,
                                           psk, psk_id)
