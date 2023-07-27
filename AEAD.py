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


class AeadApis(AbstractAead):
    """
    
    """

    @classmethod
    def Seal(cls, key, nonce, aad, pt):
        pass

    @classmethod
    def Open(cls, key, nonce, aad, ct):
        pass

    @classmethod
    @property
    @abstractmethod
    def _Nk(cls):
        return None

    @classmethod
    @property
    @abstractmethod
    def _Nn(cls):
        return None

    @classmethod
    @property
    @abstractmethod
    def _Nt(cls):
        return None


class AeadAESGCM(AeadApis):
    """
    
    """

    @classmethod
    @property
    @abstractmethod
    def _Nk(cls):
        return None

    @classmethod
    @property
    @abstractmethod
    def _Nn(cls):
        return None

    @classmethod
    @property
    @abstractmethod
    def _Nt(cls):
        return None


class AeadChaCha20Poly1305(AeadApis):
    """
    
    """

    @classmethod
    @property
    @abstractmethod
    def _Nk(cls):
        return None

    @classmethod
    @property
    @abstractmethod
    def _Nn(cls):
        return None

    @classmethod
    @property
    @abstractmethod
    def _Nt(cls):
        return None