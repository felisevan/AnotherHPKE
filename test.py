from constants import MODE_IDS, KEM_IDS, KDF_IDS, AEAD_IDS
from ContextFactory import ContextFactory
from KEM import DhKemX25519HkdfSha256
from utilities import I2OSP
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
if __name__ == '__main__':
    info = bytes.fromhex("4f6465206f6e2061204772656369616e2055726e")
    ikmR = bytes.fromhex("4b16221f3b269a88e207270b5e1de28cb01f847841b344b8314d6a622fe5ee90")
    aad = bytes.fromhex("436f756e742d30")
    nonce = bytes.fromhex("99d8b5c54669807e9fc70df1")
    pt = bytes.fromhex("4265617574792069732074727574682c20747275746820626561757479")
    psk = bytes.fromhex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82")
    psk_id = bytes.fromhex("456e6e796e20447572696e206172616e204d6f726961")
    pri, pub = DhKemX25519HkdfSha256().derive_key_pair(ikmR)
    skSm = bytes.fromhex("fc1c87d2f3832adb178b431fce2ac77c7ca2fd680f3406c77b5ecdf818b119f4")
    spri = X25519PrivateKey.from_private_bytes(skSm)
    enc, context = ContextFactory(KEM_IDS.DHKEM_X25519_HKDF_SHA256, KDF_IDS.HKDF_SHA256, AEAD_IDS.AES_128_GCM).SetupAuthPSKS(pub, info, psk, psk_id,spri)
    l = context.seal(aad, pt)
    print(l.hex())