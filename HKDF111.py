from cryptography.hazmat.primitives import hmac,hashes
from cryptography.hazmat.backends import default_backend
from utilities import concat,I2OSP,OS2IP
from modes import KDF_IDS
import HKDF


class HKDF_SHA256(HKDF):
    """
    class of HPKE's KDF compomnent
    """
    __hash = 
    def __init__(self):
        """TODO"""

    ma
    def __init__(self,KDF_ID: KDF_IDS):
        """
        TODO:docstring
        """
        match KDF_ID:           
            case KDF_IDS.HKDF_SHA256:
                self.__hash = hashes.SHA256()

            case KDF_IDS.HKDF_SHA384:
                self.__hash = hashes.SHA384()

            case KDF_IDS.HKDF_SHA512:
                self.__hash = hashes.SHA512()

            case _:
                raise NotImplementedError("An invalid KDF id found")
            
        # self.__id = 
        

    def Extract(self,SALT: bytes,IKM: bytes) -> bytes:
        """
        TODO:docstring
        """
        hctx = hmac.HMAC(SALT, self.__hash, backend=default_backend())
        return hctx.update(IKM).finalize()
    

    def Expand(self,PRK,INFO,L) -> bytes:
        """
        TODO:docstring
        """
        assert L <= 255 * self.__HASH.digest_size

        t_n_minus_1 = b""
        n = 1
        data = b""

        while len(data) < L:
            hctx = hmac.HMAC(PRK, self.__HASH, backend=default_backend())
            hctx.update(t_n_minus_1 + INFO + n.to_bytes(1, byteorder="big"))
            t_n_minus_1 = hctx.finalize()
            data += t_n_minus_1
            n += 1

        return data[:L]
    

    def LabeledExtract(self,SALT: bytes,IKM: bytes,LABEL: bytes) -> bytes:
        labeled_ikm = concat(b"HPKE-v1", suite_id, LABEL, IKM)
        return self.Extract(SALT, labeled_ikm)


    def LabeledExpand(self,PRK: bytes,LABEL: bytes,INFO: bytes,L: int) -> bytes:
        if L == 0:
            return b""

        labeled_info = concat(I2OSP(L, 2), b"HPKE-v1", suite_id, LABEL, INFO)
        return self.Expand(PRK, labeled_info, L)
    
    def get_id


#TODO : suite_id  from where?