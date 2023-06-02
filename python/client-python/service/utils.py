import ssl
import os
from pathlib import Path
from typing import Tuple

keystore_path = "C:\\Users\\BRM17037\\Downloads\\Client_Certificate_877f71bc-381f-4cef-90ea-6a41025773d2\\Client_KeyStore_sbox_877f71bc-381f-4cef-90ea-6a41025773d2.p12"
certificate_secret = 'jhv6kVrBxKIk1gwd4mL327l/ajMd0Tq4Mg6UdwQK9Mw='

def get_ssl_context() -> ssl.SSLContext:
    KEYSTORE_TYPE = "PKCS12"
    SSL_PROTOCOL = "TLS"
    keystore_path = Path(keystore_path)
    keystore_password = certificate_secret.encode()
    # Cargar el archivo de keystore en un objeto KeyStore
    client_key_store = ssl.SSLContext.load_pkcs12(keystore_path.read_bytes(), keystore_password)
    # Configurar el objeto KeyManagerFactory con el objeto KeyStore
    key_manager = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    key_manager.load_cert_chain(keystore_path, password=keystore_password)
    # Configurar el objeto SSLContext con el objeto KeyManagerFactory
    ssl_context = ssl.SSLContext(SSL_PROTOCOL)
    ssl_context.load_cert_chain(keystore_path, password=keystore_password)
    ssl_context.keymanagers = key_manager.build()
    return ssl_context

def get_ssl_context2():
    client_key_store = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    client_key_store.load_cert_chain(os.path.join(os.getcwd(), 'path/to/certfile.pem'),
                                      os.path.join(os.getcwd(), 'path/to/keyfile.pem'))
    return client_key_store
