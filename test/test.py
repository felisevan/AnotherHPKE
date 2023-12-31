import json

from src.anotherhpke.Ciphersuite import Ciphersuite
from src.anotherhpke.constants import ModeIds, AeadIds, KdfIds, KemIds


def load_test_vector():
    with open("test-vectors.json") as f:
        return json.load(f)


def bfh(x):
    return bytes.fromhex(x)


def test_asym_key(kem, ikm, sk, pk):
    pri, pub = kem.derive_key_pair(ikm)
    sk = kem.deserialize_private_key(sk)
    pk = kem.deserialize_public_key(pk)
    assert kem.serialize_private_key(pri) == kem.serialize_private_key(sk)
    assert kem.serialize_public_key(pub) == kem.serialize_public_key(pk)


def test(x):
    aead_id = AeadIds(x["aead_id"])
    kdf_id = KdfIds(x["kdf_id"])
    kem_id = KemIds(x["kem_id"])
    c = Ciphersuite(kem_id, kdf_id, aead_id)

    ikmE = bfh(x["ikmE"])
    skEm = bfh(x["skEm"])
    pkEm = bfh(x["pkEm"])
    test_asym_key(c.kem, ikmE, skEm, pkEm)
    skE = c.kem.deserialize_private_key(skEm)
    pkE = c.kem.deserialize_public_key(pkEm)

    ikmR = bfh(x["ikmR"])
    skRm = bfh(x["skRm"])
    pkRm = bfh(x["pkRm"])
    test_asym_key(c.kem, ikmR, skRm, pkRm)
    pkR = c.kem.deserialize_public_key(pkRm)

    info = bfh(x["info"])  # message to be encrypted
    enc = bfh(x["enc"])
    shared_secret = bfh(x["shared_secret"])
    key_schedule_context = bfh(x["key_schedule_context"])
    secret = bfh(x["secret"])
    key = bfh(x["key"])
    base_nonce = bfh(x["base_nonce"])
    exporter_secret = bfh(x["exporter_secret"])

    mode_id = ModeIds(x["mode"])

    match mode_id:
        case ModeIds.MODE_AUTH_PSK:
            ikmS = bfh(x["ikmS"])
            skSm = bfh(x["skSm"])
            pkSm = bfh(x["pkSm"])
            test_asym_key(c.kem, ikmS, skSm, pkSm)
            skS = c.kem.deserialize_private_key(skSm)

            psk = bfh(x["psk"])
            psk_id = bfh(x["psk_id"])

            ret_enc, ctx_sender = c.SetupAuthPSKS(
                pkR=pkR, skS=skS, psk=psk, psk_id=psk_id, info=info, skE=skE, pkE=pkE
            )
            assert enc == ret_enc

            skR = c.kem.deserialize_private_key(skRm)
            pkS = c.kem.deserialize_public_key(pkSm)
            ctx_recipient = c.SetupAuthPSKR(
                enc=enc, skR=skR, pkS=pkS, psk=psk, psk_id=psk_id, info=info
            )

        case ModeIds.MODE_AUTH:
            ikmS = bfh(x["ikmS"])
            skSm = bfh(x["skSm"])
            pkSm = bfh(x["pkSm"])
            test_asym_key(c.kem, ikmS, skSm, pkSm)
            skS = c.kem.deserialize_private_key(skSm)

            ret_enc, ctx_sender = c.SetupAuthS(
                pkR=pkR, skS=skS, info=info, skE=skE, pkE=pkE
            )
            assert enc == ret_enc

            skR = c.kem.deserialize_private_key(skRm)
            pkS = c.kem.deserialize_public_key(pkSm)
            ctx_recipient = c.SetupAuthR(enc=enc, skR=skR, pkS=pkS, info=info)

        case ModeIds.MODE_PSK:
            psk = bfh(x["psk"])
            psk_id = bfh(x["psk_id"])

            ret_enc, ctx_sender = c.SetupPSKS(
                pkR=pkR, psk=psk, psk_id=psk_id, info=info, skE=skE, pkE=pkE
            )
            assert enc == ret_enc

            skR = c.kem.deserialize_private_key(skRm)
            ctx_recipient = c.SetupPSKR(
                enc=enc, skR=skR, psk=psk, psk_id=psk_id, info=info
            )

        case ModeIds.MODE_BASE:
            ret_enc, ctx_sender = c.SetupBaseS(pkR=pkR, info=info, skE=skE, pkE=pkE)
            assert enc == ret_enc

            skR = c.kem.deserialize_private_key(skRm)
            ctx_recipient = c.SetupBaseR(enc=enc, skR=skR, info=info)

        case _:
            raise NotImplementedError

    for i in x["exports"]:
        L = i["L"]
        exported_value = bfh(i["exported_value"])
        exporter_context = bfh(i["exporter_context"])

        sender_exported_value = ctx_sender.export(exporter_context, L)
        assert exported_value == sender_exported_value

        recipient_exported_value = ctx_recipient.export(exporter_context, L)
        assert exported_value == recipient_exported_value

    for i in x["encryptions"]:
        pt = bfh(i["pt"])
        nonce = bfh(i["nonce"])
        aad = bfh(i["aad"])
        ct = bfh(i["ct"])

        ret_ct = ctx_sender.seal(pt, aad)
        assert ct == ret_ct

        ret_pt = ctx_recipient.open(ct, aad)
        assert pt == ret_pt


if __name__ == "__main__":
    test_vectors = load_test_vector()
    for i in test_vectors:
        test(i)
