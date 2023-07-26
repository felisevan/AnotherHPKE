from modes import *
import KEM,KDF,AEAD

class ciphersuite(object):
    """
    HPKE cipher suite composed by triple (KEM,KDF,AEAD)
    """

    def __init__(self, KEM_ID: KEM_IDS, KDF_ID: KEM_IDS, AEAD_ID: AEAD_IDS):
        self.__kem_id = KEM_ID
        self.__KDF_id = KDF_ID
        self.__aead_id = AEAD_ID

    @classmethod
    def initial(self, KEM_ID: KEM_IDS, KDF_ID: KEM_IDS, AEAD_ID: AEAD_IDS):
        self.__kem_id = KEM(KEM_ID)
        self.__kdf_id = KDF(KDF_ID)
        self.__aead_id  = AEAD(AEAD_ID)
        pass