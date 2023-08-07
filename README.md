# AnotherHPKE

HPKE((**Hybrid Public Key Encryption**)) implementation in **_Python3_** and package **_cryptography_** according
to  [RFC 9180](https://www.ietf.org/rfc/rfc9180.pdf).

#### 😭Please give us undergraduate students a little star, hoping this project meets your needs.😋

#### 🥰Your recognition and support matters! 🥰

# Background

HPKE component was needed when building one of our other projects, ~~but we didn't find an easy-to-use and complete HPKE
implementation~~ which gave us the incentive to implement this project in python following the RFC documentation and
other authors' experience.

# Announcement

Inspired by
_[Universal Declaration of Human Rights](https://www.un.org/en/about-us/universal-declaration-of-human-rights)_
and
_[17 SDG goals](https://sdgs.un.org/goals)_,
we contribute to this project in the position of safeguarding the common interests and universal values of all
humankind.
---

### Stand with Ukraine

# Dependency

This project simply uses **_python3_** with package **_cryptography_**.

* pip  
  `pip install cryptography`

***

* conda  
  `conda install -c anaconda cryptography`   
  or  
  `conda install -c conda-forge cryptography`

# Usage

```python
from src.anotherhpke.Context import ContextFactory
from src.anotherhpke import KEM_IDS, KDF_IDS, AEAD_IDS
import os

ctx_factory = ContextFactory(KEM_IDS.DHKEM_X25519_HKDF_SHA256, KDF_IDS.HKDF_SHA256, AEAD_IDS.ChaCha20Poly1305)
sender_pri, sender_pub = ctx_factory.kem.derive_key_pair(os.urandom(32))
recipient_pri, recipient_pub = ctx_factory.kem.derive_key_pair(os.urandom(32))

# Sender side
enc, ctx = ctx_factory.SetupBaseS(recipient_pub)
encrypted = ctx.seal(b"plain text")

# Recipient side
ctx = ctx_factory.SetupBaseR(enc, recipient_pri)
decrypted = ctx.open(encrypted)
```

# Badge

# Related Efforts

[hpke-py](https://github.com/ctz/hpke-py/)  
[pyhpke](https://github.com/dajiaji/pyhpke)

# Author

[@felisevan](https://github.com/felisevan)  
[@14MBD4](https://github.com/14MBD4)

# License

[AGPL-3.0 license](https://www.gnu.org/licenses/agpl-3.0-standalone.html)