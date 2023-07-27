from collections import namedtuple

CipherSuite = namedtuple("CipherSuite", ["KEM_ID", "KDF_ID", "AEAD_ID"])
