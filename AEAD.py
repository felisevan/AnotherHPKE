from abc import ABC, abstractmethod


class AbstractAead(ABC):
    """

    """

    @classmethod
    @abstractmethod
    def Seal(cls, key, nonce, aad, pt):
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def Open(cls, key, nonce, aad, ct):
        raise NotImplementedError



class AesGcm(AbstractAead):
    """
    
    """

    @classmethod
    @abstractmethod
    def Seal(cls, key, nonce, aad, pt):
        pass

    @classmethod
    @abstractmethod
    def Open(cls, key, nonce, aad, ct):
        pass

    @classmethod
    @property
    @abstractmethod
    def _Nk(cls):
        raise NotImplementedError

    @classmethod
    @property
    @abstractmethod
    def _Nn(cls):
        raise NotImplementedError

    @classmethod
    @property
    @abstractmethod
    def _Nt(cls):
        raise NotImplementedError



class ChaCha20Poly1305(AbstractAead):
    """
    
    """

    @classmethod
    @abstractmethod
    def Seal(cls, key, nonce, aad, pt):
        pass

    @classmethod
    @abstractmethod
    def Open(cls, key, nonce, aad, ct):
        pass

    @classmethod
    @property
    @abstractmethod
    def _Nk(cls):
        raise NotImplementedError

    @classmethod
    @property
    @abstractmethod
    def _Nn(cls):
        raise NotImplementedError

    @classmethod
    @property
    @abstractmethod
    def _Nt(cls):
        raise NotImplementedError
    


class AeadAes256Gcm(AesGcm):
    """
    
    """

    @classmethod
    @property
    def _Nk(cls):
        pass

    @classmethod
    @property
    def _Nn(cls):
        pass

    @classmethod
    @property
    def _Nt(cls):
        pass



class AeadAes128Gcm(AesGcm):
    """
    
    """

    @classmethod
    @property
    def _Nk(cls):
        pass

    @classmethod
    @property
    def _Nn(cls):
        pass

    @classmethod
    @property
    def _Nt(cls):
        pass



class AeadChaCha20Poly1305(ChaCha20Poly1305):
    """
    
    """

    @classmethod
    @property
    def _Nk(cls):
        pass

    @classmethod
    @property
    def _Nn(cls):
        pass

    @classmethod
    @property
    def _Nt(cls):
        pass