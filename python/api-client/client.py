# Usar archivo properties en lugar de constantes
# No versionar en el repositorio datos para las propiedades variables como clientId
import logging
import tempfile

import requests

from util import encryption, certificate
from util.encryption import EncryptionModel

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(asctime)s -> %(message)s')
log = logging.getLogger('client')

API_HOST = "https://sbox-open-api.banregio.com"
B_APPLICATION = "5937a4bf-40c9-470e-b79b-c646c9b3d548"
API_BASE_PATH = "/datr/v1.0"
API_NAME = "/account-access-consents"

MTLS_P12_PATH = "/Users/BRM14355/Code/Client_Certificate_Datr/Client_KeyStore_sbox_cab1da7a-dbef-41bb-8824-eb14aa079ae3.p12"
MTLS_P12_PASSWD = "YDs/+ExqvS0xN3thWpu8GisqJz/aVCsl5FX53SV7X8I="

TOKEN_HOST = "https://sbox-open-api.banregio.com"
TOKEN_BASE_PATH = "/auth/v1/oidc"
TOKEN_NAME = "/token"
TOKEN_GRANT_TYPE = "client_credentials"
TOKEN_AUTH_TYPE = "Bearer"

SUBSCRIPTION_CLIENT_ID = "5937a4bf-40c9-470e-b79b-c646c9b3d548"
SUBSCRIPTION_CLIENT_SECRET = "4472c868-d72f-41ed-93ab-2ac7459ebe9c"
SUBSCRIPTION_B_APPLICATION = "cab1da7a-dbef-41bb-8824-eb14aa079ae3"


def do_request(endpoint: str, payload, headers):
    log.info("Request: {}".format(endpoint))
    client_private_key = tempfile.NamedTemporaryFile()
    client_public_key = tempfile.NamedTemporaryFile()
    certificate.p12_to_pem(MTLS_P12_PATH, MTLS_P12_PASSWD, client_private_key, client_public_key)

    response = requests.request(
        'POST',
        headers=headers,
        url=endpoint,
        data=payload,
        cert=(client_public_key.name, client_private_key.name))

    log.info("Response: {} {}".format(response.status_code, response.reason))
    log.info(response.json())
    return response


def get_token():
    log.info("Generating token ...")
    token_endpoint = TOKEN_HOST + TOKEN_BASE_PATH + TOKEN_NAME
    payload = {'grant_type': TOKEN_GRANT_TYPE,
               'client_id': SUBSCRIPTION_CLIENT_ID,
               'client_secret': SUBSCRIPTION_CLIENT_SECRET}
    response = do_request(token_endpoint, payload, None)
    token = response.json()["access_token"]
    return f"{TOKEN_AUTH_TYPE} {token}"


if __name__ == "__main__":
    client_private_key = "/Users/BRM14355/Code/Client_Certificate_Datr/Client_sbox_privateKey.pem"
    server_public_key = "/Users/BRM14355/Code/Client_Certificate_Datr/Server_Public_sbox_cab1da7a-dbef-41bb-8824-eb14aa079ae3.pem"

    request_model = EncryptionModel('{"AccountNumber": "220008880018"}', client_private_key, server_public_key,
                                    SUBSCRIPTION_B_APPLICATION)
    request_payload = encryption.sign_and_encrypt_payload(request_model)
    request_payload = '{"data":' + ' "' + request_payload + '"}'

    headers = {
        'Authorization': get_token(),
        'B-Application': SUBSCRIPTION_B_APPLICATION,
        'B-Transaction': "12345678",
        'B-Option': "0",
        'Content-Type': "application/json",
        'Accept-Charset': "UTF-8",
        'Accept': "application/json"
    }
    api_endpoint = API_HOST + API_BASE_PATH + API_NAME
    do_request(api_endpoint, request_payload, headers)
