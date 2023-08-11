import json
from pprint import pprint

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
    aead_id = AeadIds(x['aead_id'])
    if aead_id == AeadIds.Export_only:
        print("Export only")
        return
    kdf_id = KdfIds(x['kdf_id'])
    kem_id = KemIds(x['kem_id'])
    c = Ciphersuite(kem_id, kdf_id, aead_id)

    ikmE = bfh(x['ikmE'])
    skEm = bfh(x['skEm'])
    pkEm = bfh(x['pkEm'])
    test_asym_key(c.kem, ikmE, skEm, pkEm)
    skE = c.kem.deserialize_private_key(skEm)
    pkE = c.kem.deserialize_public_key(pkEm)

    ikmR = bfh(x['ikmR'])
    skRm = bfh(x['skRm'])
    pkRm = bfh(x['pkRm'])
    test_asym_key(c.kem, ikmR, skRm, pkRm)
    pkR = c.kem.deserialize_public_key(pkRm)

    info = bfh(x['info'])  # message to be encrypted
    enc = bfh(x['enc'])
    shared_secret = bfh(x['shared_secret'])
    key_schedule_context = bfh(x['key_schedule_context'])
    secret = bfh(x['secret'])
    key = bfh(x['key'])
    base_nonce = bfh(x['base_nonce'])
    exporter_secret = bfh(x['exporter_secret'])

    mode_id = ModeIds(x['mode'])

    match mode_id:
        case ModeIds.MODE_AUTH_PSK:
            ikmS = bfh(x['ikmS'])
            skSm = bfh(x['skSm'])
            pkSm = bfh(x['pkSm'])
            test_asym_key(c.kem, ikmS, skSm, pkSm)
            skS = c.kem.deserialize_private_key(skSm)

            psk = bfh(x['psk'])
            psk_id = bfh(x['psk_id'])

            ret_enc, ctx = c.SetupAuthPSKS(
                pkR=pkR,
                skS=skS,
                psk=psk,
                psk_id=psk_id,
                info=info,
                skE=skE,
                pkE=pkE
            )
            assert enc == ret_enc

        case ModeIds.MODE_AUTH:
            ikmS = bfh(x['ikmS'])
            skSm = bfh(x['skSm'])
            pkSm = bfh(x['pkSm'])
            test_asym_key(c.kem, ikmS, skSm, pkSm)
            skS = c.kem.deserialize_private_key(skSm)

            ret_enc, ctx = c.SetupAuthS(
                pkR=pkR,
                skS=skS,
                info=info,
                skE=skE,
                pkE=pkE
            )
            assert enc == ret_enc

        case ModeIds.MODE_PSK:
            psk = bfh(x['psk'])
            psk_id = bfh(x['psk_id'])

            ret_enc, ctx = c.SetupPSKS(
                pkR=pkR,
                psk=psk,
                psk_id=psk_id,
                info=info,
                skE=skE,
                pkE=pkE
            )
            assert enc == ret_enc

        case ModeIds.MODE_BASE:
            ret_enc, ctx = c.SetupBaseS(
                pkR=pkR,
                info=info,
                skE=skE,
                pkE=pkE
            )
            assert enc == ret_enc

        case _:
            raise NotImplementedError

    for i in x['encryptions']:
        pt = bfh(i['pt'])
        nonce = bfh(i['nonce'])
        aad = bfh(i['aad'])
        ct = bfh(i['ct'])

        ret_ct = ctx.seal(pt, aad)
        assert ct == ret_ct


if __name__ == '__main__':
    test_vectors = load_test_vector()
    for k, v in enumerate(test_vectors):
        print(k)
        test(v)
