from collections import namedtuple

CipherSuite = namedtuple("CipherSuite", ["KEM", "KDF", "AEAD"])
