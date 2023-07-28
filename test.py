from constants import MODE_IDS, KEM_IDS, KDF_IDS, AEAD_IDS
from ContextFactory import ContextFactory
from KEM import DhKemX25519HkdfSha256
from utilities import I2OSP

if __name__ == '__main__':
    info = bytes.fromhex("4f6465206f6e2061204772656369616e2055726e")
    pkRm = bytes.fromhex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
    skRm = bytes.fromhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
    a = ContextFactory(KEM_IDS.DHKEM_X25519_HKDF_SHA256, KDF_IDS.HKDF_SHA256, AEAD_IDS.AES_128_GCM)
    enc, sender = a.SetupBaseS(DhKemX25519HkdfSha256().deserialize_public_key(pkRm), info)
    print(enc)