import logging

from authlib.jose import JsonWebSignature
from authlib.jose import JsonWebEncryption
from authlib.jose import errors

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(asctime)s -> %(message)s')
log = logging.getLogger('client')


jwe = JsonWebEncryption()
jws = JsonWebSignature()
JWE_ALGORITHM = 'RSA-OAEP-256'
JWS_ALGORITHM = 'RS256'


def read_private_key(private_key):
    """Read private key file and convert to bytes
        :param private_key: A string of private key
        :return: byte
    """
    try:
        with open(private_key, 'rb') as f:
            private_pem = f.read()
            return private_pem
    except FileNotFoundError:
        print('An error occurred while reading private key')
        exit()


def read_public_key(public_key):
    """ Read public key file and convert to bytes
        :param public_key: A string of public key
        :return: byte
    """
    try:
        with open(public_key, 'rb') as f:
            public_pem = f.read()
            return public_pem
    except FileNotFoundError:
        print('An error occurred while reading public key')
        exit()


def sign_and_encrypt_payload(request_model):
    """ Sign and encrypt payload bytes.
        :param request_model: A model with the parameters
        :return: str
    """
    log.info("Encrypting and Signing request payload ...")
    if isinstance(request_model, EncryptionModel):
        try:
            #payload = bytes(input("abc"), 'utf-8')
            private_pem = read_private_key(request_model.private_key)
            public_pem = read_public_key(request_model.public_key)
            header_sign = {'alg': JWS_ALGORITHM, 'kid': request_model.b_application}
            header_encrypt = {'alg': JWE_ALGORITHM, 'enc': 'A256GCM', 'kid': request_model.b_application}

            payload_signed = jws.serialize_compact(header_sign, str(request_model.payload).encode('utf-8'), private_pem)
            payload_encrypted = jwe.serialize_compact(header_encrypt, payload_signed, public_pem)

            return payload_encrypted.decode("utf-8")
        except ValueError:
            raise Exception("Encryption and signature failed")
    else:
        raise Exception("request_model argument must be instance of EncryptionModel class")


def decrypt_and_verify_sign_payload(request_model):
    """ Decrypt and verify sign payload bytes.
        :param request_model: A model with the parameters
        :return: str
    """
    log.info("Decrypting and Verifying signature request payload ...")
    if isinstance(request_model, EncryptionModel):
        print(type(request_model.payload))
        try:
            private_pem = read_private_key(request_model.private_key)
            public_pem = read_public_key(request_model.public_key)
            data = jwe.deserialize_compact(request_model.payload, private_pem)
            payload_decrypted = data['payload']
            data = jws.deserialize_compact(payload_decrypted, public_pem)
            payload_verified = data['payload']
            return payload_verified
        except (ValueError, errors.DecodeError):
            raise Exception("Decryption and signature verification failed.")
    else:
        raise Exception("request_model argument must be instance of EncryptionModel class")


class EncryptionModel:
    def __init__(self, payload, private_key, public_key, b_application):
        """
        Attributes
        ----------
        payload : str
            The payload used for encryption or decryption
        private_key : str
            The client public key(certificate) file
        public_key : str
            The client private key file
        b_application : str
            The identifier of the application corresponding to API subscription
        """
        self.payload = payload
        self.private_key = private_key
        self.public_key = public_key
        self.b_application = b_application
