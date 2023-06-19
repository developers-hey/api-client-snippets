import logging

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(asctime)s -> %(message)s')
log = logging.getLogger('certificate')


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
