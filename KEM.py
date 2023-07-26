from modes import KEM_IDS

class KEM:
    """
    class of HPKE's KEM compomnent
    """

    def __init__(self,KEM_ID: KEM_IDS):
        """
        :param Nsecret: length of shared secret produced by KEM
        :param Nenc: length of encapsulated key produced by KEM
        :param Npk: length of encoded public key for KEM
        :param Nsk: length of encoded private key for KEM
        :return: 
        """
        
    @property
    def KEM_ID(self):
        # TODO: docstring
        pass