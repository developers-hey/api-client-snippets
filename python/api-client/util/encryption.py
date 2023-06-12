import logging

from authlib.jose import JsonWebSignature
from authlib.jose import JsonWebEncryption
from authlib.jose import errors

from util.certificate import read_private_key, read_public_key

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(asctime)s -> %(message)s')
log = logging.getLogger('encryption')

jwe = JsonWebEncryption()
jws = JsonWebSignature()
JWE_ALGORITHM = 'RSA-OAEP-256'
JWS_ALGORITHM = 'RS256'


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

        payload_signed = jws.serialize_compact(header_sign, payload.encode('utf-8'), private_pem)
        payload_encrypted = jwe.serialize_compact(header_encrypt, payload_signed, public_pem)

        return '{"data":' + ' "' + payload_encrypted.decode("utf-8") + '"}'
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
        payload_decrypted = data['payload']
        data = jws.deserialize_compact(payload_decrypted, public_pem)
        payload_verified = data['payload']
        return payload_verified.decode("utf-8")
    except (ValueError, errors.DecodeError):
        raise Exception("Decryption and signature verification failed.")
