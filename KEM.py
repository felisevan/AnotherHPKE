from modes import KEM_IDS

class KEM(object):
    """
    class of HPKE's KEM compomnent
    """

    def __init__(self,KEM_ID: KEM_IDS):
        """
        parameters:
                Nsecret: length of shared secret produced by KEM
                Nenc: length of encapsulated key produced by KEM
                Npk: length of encoded public key for KEM
                Nsk: length of encoded private key for KEM
        """
        
    @property
    def KEM_ID(self):
        pass