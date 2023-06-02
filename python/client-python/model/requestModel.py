class requestModel:
    def __init__(self, payload, private_key, public_key, b_application):
        """
        Parameters
        ----------
        payload : str
            The payload used for encryption or decryption
        private_key : str
            The public key file
        public_key : str
            The public key file
        b_application : str
            The identifier of the application corresponding to the certificates
        """
        self.payload = payload
        self.private_key = private_key
        self.public_key = public_key
        self.b_application = b_application