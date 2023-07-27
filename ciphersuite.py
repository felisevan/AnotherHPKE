import AEAD
import HKDF111
import KEM
from modes import *


class ciphersuite:
    """
    HPKE cipher suite composed by triple (KEM,KDF,AEAD)
    """

    def __init__(self, KEM_ID: KEM_IDS, KDF_ID: KEM_IDS, AEAD_ID: AEAD_IDS):
        # TODO: docstring
        self.__kem_id = KEM_ID
        self.__KDF_id = KDF_ID
        self.__aead_id = AEAD_ID

    @classmethod
    def initial(self, KEM_ID: KEM_IDS, KDF_ID: KEM_IDS, AEAD_ID: AEAD_IDS):
        # TODO: docstring
        self.__kem_id = KEM(KEM_ID)
        self.__kdf_id = HKDF111(KDF_ID)
        self.__aead_id = AEAD(AEAD_ID)
        pass
