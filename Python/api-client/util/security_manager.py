import logging

from authlib.jose import JsonWebSignature
from authlib.jose import JsonWebEncryption
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(asctime)s -> %(message)s')
log = logging.getLogger('certificate')

jwe = JsonWebEncryption()
jws = JsonWebSignature()
JWE_ALGORITHM = 'RSA-OAEP-256'
JWS_ALGORITHM = 'RS256'


def convert_p12_to_pem(p12_path, p12_passwd, key_pem, cer_pem):
    with open(p12_path, "rb") as p12:
        (private_key, public_key, additional_certs) = pkcs12.load_key_and_certificates(p12.read(), p12_passwd.encode())
        log.debug("KEY {}".format(private_key))
        log.debug("CER {}".format(public_key))

        key_pem.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
        key_pem.flush()
        cer_pem.write(public_key.public_bytes(serialization.Encoding.PEM))
        cer_pem.flush()


def read_private_key(private_key):
    """Read private key file and convert to bytes
        :param private_key: A string of private key
        :return: byte
    """
    try:
        with open(private_key, 'rb') as f:
            private_pem = f.read()
            return private_pem
    except FileNotFoundError as ex:
        log.warning('An error occurred while reading private key {} '.format(ex))


def read_public_key(public_key):
    """ Read public key file and convert to bytes
        :param public_key: A string of public key
        :return: byte
    """
    try:
        with open(public_key, 'rb') as f:
            public_pem = f.read()
            return public_pem
    except FileNotFoundError as ex:
        log.warning('An error occurred while reading public key {} '.format(ex))


def sign_and_encrypt_payload(payload, b_application, client_private_key, server_public_key):
    """ Sign and encrypt payload bytes.
        :param client_private_key: Client private key to use for sign encryption
        :param server_public_key: Server public key(certificate) to use for encrypt
        :param payload: Plain request payload
        :param b_application B-Application assigned to the subscription
        :return: str
    """
    log.info("Encrypting and Signing request payload ...")
    try:
        private_pem = read_private_key(client_private_key)
        public_pem = read_public_key(server_public_key)
        header_sign = {'alg': JWS_ALGORITHM, 'kid': b_application}
        header_encrypt = {'alg': JWE_ALGORITHM, 'enc': 'A256GCM', 'kid': b_application}

        signed_payload = jws.serialize_compact(header_sign, payload.encode('utf-8'), private_pem)
        encrypted_payload = jwe.serialize_compact(header_encrypt, signed_payload, public_pem)

        return '{"data":' + ' "' + encrypted_payload.decode("utf-8") + '"}'
    except ValueError:
        raise Exception("Encryption and signature failed")


def decrypt_and_verify_sign_payload(payload, client_private_key, server_public_key):
    """ Decrypt and verify sign payload bytes.
        :param client_private_key: Client private key to use for decrypt
        :param server_public_key: Server public key(certificate) to use for verify sign
        :param payload: Encrypted response payload
        :return: str
    """
    log.info("Decrypting and Verifying signature request payload ...")
    try:
        private_pem = read_private_key(client_private_key)
        public_pem = read_public_key(server_public_key)
        data = jwe.deserialize_compact(payload.encode('utf-8'), private_pem)
        decrypted_payload = data['payload']
        data = jws.deserialize_compact(decrypted_payload, public_pem)
        verified_payload = data['payload']
        return verified_payload.decode("utf-8")
    except (ValueError, errors.DecodeError):
        raise Exception("Decryption and signature verification failed.")
