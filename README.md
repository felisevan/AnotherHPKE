# AnotherHPKE

HPKE((**Hybrid Public Key Encryption**)) implementation in **_Python3_** and package **_cryptography_** according
to  [RFC 9180](https://www.ietf.org/rfc/rfc9180.pdf).


# Usage

```python
from src.anotherhpke import Ciphersuite, KemIds, KdfIds, AeadIds
import os

ciphersuite = Ciphersuite(KemIds.DHKEM_X25519_HKDF_SHA256, KdfIds.HKDF_SHA256, AeadIds.ChaCha20Poly1305)
sender_pri, sender_pub = ciphersuite.kem.derive_key_pair(os.urandom(32))
recipient_pri, recipient_pub = ciphersuite.kem.derive_key_pair(os.urandom(32))

# Sender side
enc, ctx = ciphersuite.SetupBaseS(recipient_pub)
encrypted = ctx.seal(b"plain text")

# Recipient side
ctx = ciphersuite.SetupBaseR(enc, recipient_pri)
decrypted = ctx.open(encrypted)
```

# Feature Matrix

 - Modes
   - [x] mode_base
   - [x] mode_psk
   - [x] mode_auth
   - [x] mode_auth_psk
 - AEADs
   - [x] AES-128-GCM
   - [x] AES-256-GCM
   - [x] ChaCha20Poly1305
   - [ ] AES-256-SIV (Draft only, don't recommend for production use, see [this](https://datatracker.ietf.org/doc/draft-irtf-cfrg-dnhpke/03/))
   - [ ] AES-512-SIV (Draft only, don't recommend for production use, see [this](https://datatracker.ietf.org/doc/draft-irtf-cfrg-dnhpke/03/))
   - [x] Export only
 - KEMs
   - [x] DHKEM(P-256, HKDF-SHA256)
   - [x] DHKEM(P-384, HKDF-SHA384)
   - [x] DHKEM(P-521, HKDF-SHA512)
   - [x] DHKEM(X25519, HKDF-SHA256)
   - [x] DHKEM(X448, HKDF-SHA512)
   - [ ] DHKEM(CP-256, HKDF-SHA256)
   - [ ] DHKEM(CP-384, HKDF-SHA384)
   - [ ] DHKEM(CP-521, HKDF-SHA512)
   - [x] DHKEM(secp256k1, HKDF-SHA256)
   - [ ] X25519Kyber768Draft00
 - KDFs
   - [x] HKDF-SHA256
   - [x] HKDF-SHA384
   - [x] HKDF-SHA512

  Just FYI, our project have a working `derive_key_pair` function for each implemented KEMs.

# Dependency

This project simply uses **_python3_** with package **_cryptography_**.

* pip  
  `pip install cryptography`

***

* conda  
  `conda install -c anaconda cryptography`   
  or  
  `conda install -c conda-forge cryptography`

# License

[AGPL-3.0 license](https://www.gnu.org/licenses/agpl-3.0-standalone.html)