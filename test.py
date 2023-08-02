import json
from pprint import pprint

from Context import ContextFactory
from constants import MODE_IDS, KEM_IDS, KDF_IDS, AEAD_IDS


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
    aead_id = AEAD_IDS(x['aead_id'])
    kdf_id = KDF_IDS(x['kdf_id'])
    kem_id = KEM_IDS(x['kem_id'])
    c = ContextFactory(kem_id, kdf_id, aead_id)

    ikmR = bfh(x['ikmR'])
    skRm = bfh(x['skRm'])
    pkRm = bfh(x['pkRm'])
    test_asym_key(c.kem, ikmR, skRm, pkRm)

    ikmE = bfh(x['ikmE'])
    skEm = bfh(x['skEm'])
    pkEm = bfh(x['pkEm'])
    test_asym_key(c.kem, ikmE, skEm, pkEm)

    info = bfh(x['info'])  # message to be encrypted
    enc = bfh(x['enc'])  # should be same as pkEm
    shared_secret = bfh(x['shared_secret'])  # crypt state
    key_schedule_context = bfh(x['key_schedule_context'])
    secret = bfh(x['secret'])
    key = bfh(x['key'])
    base_nonce = bfh(x['base_nonce'])
    exporter_secret = bfh(x['exporter_secret'])
    mode_id = MODE_IDS(x['mode'])

    match mode_id:
        case MODE_IDS.MODE_AUTH_PSK:
            ikmS = bfh(x['ikmS'])
            skSm = bfh(x['skSm'])
            pkSm = bfh(x['pkEm'])
            test_asym_key(c.kem, ikmS, skSm, pkSm)

            psk = bfh(x['psk'])
            psk_id = bfh(x['psk_id'])

        case MODE_IDS.MODE_AUTH:
            ikmS = bfh(x['ikmS'])
            skSm = bfh(x['skSm'])
            pkSm = bfh(x['pkEm'])
            test_asym_key(c.kem, ikmS, skSm, pkSm)

        case MODE_IDS.MODE_PSK:
            psk = bfh(x['psk'])
            psk_id = bfh(x['psk_id'])

        case MODE_IDS.MODE_BASE:
            print()

        case _:
            raise NotImplementedError


if __name__ == '__main__':
    test_vectors = load_test_vector()
    pprint(test_vectors[3])
