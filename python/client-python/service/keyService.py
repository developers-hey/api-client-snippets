from authlib.jose import JsonWebSignature
from authlib.jose import JsonWebEncryption
from authlib.jose import errors


jwe = JsonWebEncryption()
jws = JsonWebSignature()
jwe_algorithm = 'RSA-OAEP-256'
jws_algorithm = 'RS256'


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
        :return: byte
    """
    try:
        #
        private_pem = read_private_key(request_model.private_key)
        public_pem = read_public_key(request_model.public_key)
        header_sign = {'alg': jws_algorithm, 'kid': request_model.b_application}
        header_encrypt = {'alg': jwe_algorithm, 'enc': 'A256GCM', 'kid': request_model.b_application}
        payload_signed = jws.serialize_compact(header_sign, request_model.payload, private_pem)
        payload_encrypted = jwe.serialize_compact(header_encrypt, payload_signed, public_pem)
        return payload_encrypted
    except ValueError:
        return b'Encryption and signature failed'


def decrypt_and_verify_sign_payload(request_model):
    """ Decrypt and verify sign payload bytes.
        :param request_model: A model with the parameters
        :return: byte
    """
    try:
        private_pem = read_private_key(request_model.private_key)
        public_pem = read_public_key(request_model.public_key)
        data = jwe.deserialize_compact(request_model.payload, private_pem)
        payload_decrypted = data['payload']
        data = jws.deserialize_compact(payload_decrypted, public_pem)
        payload_verified = data['payload']
        return payload_verified
    except (ValueError, errors.DecodeError):
        return b'Decryption and verification failed.'