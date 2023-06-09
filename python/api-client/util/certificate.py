import contextlib
import logging
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(asctime)s -> %(message)s')
log = logging.getLogger('mtls')


def p12_to_pem(p12_path, p12_passwd, key_pem, cer_pem):
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

