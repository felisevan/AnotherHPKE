from abc import ABC, abstractmethod
from cryptography.hazmat.primitives import hmac,hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF,HKDFExpand
from utilities import concat,I2OSP,OS2IP        #TODO import error

class AbstractHkdf(ABC):

    @classmethod
    @abstractmethod
    def extract(cls,salt: bytes,ikm: bytes,info: bytes = b"") -> bytes:
        raise NotImplementedError
    
    @classmethod
    @abstractmethod
    def expand(cls, prk: bytes, L: int,info: bytes = b"") -> bytes:
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def labeled_extract(cls,salt: bytes,ikm: bytes,label: bytes, suite_id: bytes) -> bytes:
        raise NotImplementedError
    
    @classmethod
    @abstractmethod
    def labeled_expand(cls,prk: bytes,label: bytes,info: bytes,L: int, suite_id: bytes) -> bytes:
        raise NotImplementedError
    



class Hkdf_SHA256(AbstractHkdf):
    """
    class of HPKE's KDF compomnent
    """

    __hash = hashes.SHA256()
    __Nh = 32


    @classmethod
    def extract(cls, salt: bytes, ikm: bytes,info: bytes = b"") -> bytes:
        hkdf = HKDF(
                    algorithm = cls.__hash,
                    length = cls.__Nh,
                    salt = salt,
                    info = info,                         #TODO info optional  KEM
                    )
        key = hkdf.derive(ikm)
        return key
        #TODO verify(key_material, expected_key) cryptography.io :HKDF
        #TODO bigend????
    
    @classmethod
    def expand(cls, prk: bytes, L: int,info: bytes = b"") -> bytes:
        hkdf = HKDFExpand(
                    algorithm=cls.__hash,
                    length=L,
                    info=info,                  #info :optional string
                    )
        key = hkdf.derive(prk)
        return key
    
    @classmethod
    def labeled_extract(self, salt: bytes, ikm: bytes, label: bytes,suite_id: bytes) -> bytes:
        labeled_ikm = concat(b"HPKE-v1", suite_id, label, ikm)
        return self.Extract(salt, labeled_ikm)
    
    @classmethod
    def labeled_expand(self, prk: bytes, label: bytes, info: bytes, L: int,suite_id: bytes) -> bytes:
        
        if L == 0:
            return b""

        labeled_info = concat(I2OSP(L, 2), b"HPKE-v1", suite_id, label, info)
        return self.Expand(prk, labeled_info, L)
    
    @classmethod
    def get_Nh(cls):
        return cls.__Nh
    



class Hkdf_SHA384(AbstractHkdf):
    """
    
    """

    __hash = hashes.SHA256()
    __Nh = 48


    @classmethod
    def extract(cls, salt: bytes, ikm: bytes,info: bytes = b"") -> bytes:
        hkdf = HKDF(
                    algorithm = cls.__hash,
                    length = cls.__Nh,
                    salt = salt,
                    info = info,
                    )
        key = hkdf.derive(ikm)
        return key
    
    @classmethod
    def expand(cls, prk: bytes, L: int,info: bytes = b"") -> bytes:
        hkdf = HKDFExpand(
                    algorithm=cls.__hash,
                    length=L,
                    info=info,    
                    )
        key = hkdf.derive(prk)
        return key

    @classmethod
    def labeled_extract(self, salt: bytes, ikm: bytes, label: bytes,suite_id: bytes) -> bytes:
        labeled_ikm = concat(b"HPKE-v1", suite_id, label, ikm)
        return self.Extract(salt, labeled_ikm)
    
    @classmethod
    def labeled_expand(self, prk: bytes, label: bytes, info: bytes, L: int,suite_id: bytes) -> bytes:
        
        if L == 0:
            return b""

        labeled_info = concat(I2OSP(L, 2), b"HPKE-v1", suite_id, label, info)
        return self.Expand(prk, labeled_info, L)
    
    @classmethod
    def get_Nh(cls):
        return cls.__Nh




class Hkdf_SHA512(AbstractHkdf):
    """
    
    """

    __hash = hashes.SHA512()
    __Nh = 64


    @classmethod
    def extract(cls, salt: bytes, ikm: bytes,info: bytes = b"") -> bytes:
        hkdf = HKDF(
                    algorithm = cls.__hash,
                    length = cls.__Nh,
                    salt = salt,
                    info = info,
                    )
        key = hkdf.derive(ikm)
        return key
    
    @classmethod
    def expand(cls, prk: bytes, L: int,info: bytes = b"") -> bytes:
        hkdf = HKDFExpand(
                    algorithm=cls.__hash,
                    length=L,
                    info=info,    
                    )
        key = hkdf.derive(prk)
        return key

    @classmethod
    def labeled_extract(self, salt: bytes, ikm: bytes, label: bytes,suite_id: bytes) -> bytes:
        labeled_ikm = concat(b"HPKE-v1", suite_id, label, ikm)
        return self.Extract(salt, labeled_ikm)
    
    @classmethod
    def labeled_expand(self, prk: bytes, label: bytes, info: bytes, L: int,suite_id: bytes) -> bytes:
        
        if L == 0:
            return b""

        labeled_info = concat(I2OSP(L, 2), b"HPKE-v1", suite_id, label, info)
        return self.Expand(prk, labeled_info, L)
    
    @classmethod
    def get_Nh(cls):
        return cls.__Nh