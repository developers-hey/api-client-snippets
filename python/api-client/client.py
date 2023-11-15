import configparser
import logging
import tempfile

import requests

from util import security_manager


def do_request(http_verb: str, endpoint: str, request_payload: str, headers: dict, sendPayload: bool,
               payload_encryption: bool):
    log.info("===============================================================")
    log.info("Request {}: {}".format(http_verb, endpoint))
    log.info("Headers: [{}]".format(headers))
    success_response_200 = 200
    success_response_201 = 201
    b_trace_header = "b-trace"
    location_header = "location"

    client_private_key = tempfile.NamedTemporaryFile()
    client_public_key = tempfile.NamedTemporaryFile()
    security_manager.convert_p12_to_pem(config['MTLS']['KEYSTORE_PATH'], config['MTLS']['KEYSTORE_PASSWD'],
                                        client_private_key, client_public_key)

    if payload_encryption and sendPayload:
        request_payload = security_manager.sign_and_encrypt_payload(request_payload,
                                                                    config['SUBSCRIPTION']['B_APPLICATION'],
                                                                    client_private_key.name,
                                                                    config['JWE']['SERVER_PUBLICKEY'])

    try:
        response = requests.request(
            http_verb,
            headers=headers,
            url=endpoint,
            data=request_payload if sendPayload else "",
            cert=(client_public_key.name, client_private_key.name))

        log.info("Response: {} {}".format(response.status_code, response.reason))
        if payload_encryption and response.status_code == success_response_200:
            response_payload = {"code": response.json()["code"], "message": response.json()["message"],
                                "data": security_manager.decrypt_and_verify_sign_payload(response.json()["data"],
                                                                                         client_private_key.name,
                                                                                         config['JWE'][
                                                                                             'SERVER_PUBLICKEY'])}
            log.info(response_payload)
        else:
            log.info(response.json())

        # Print relevant headers, for example: Locations contains the resource ID that have been created with POST
        if b_trace_header in response.headers:
            log.info("Header: [{}={}]".format(b_trace_header, response.headers[b_trace_header]))
        if response.status_code == success_response_201 and location_header in response.headers:
            log.info("Header: [{}={}]".format(location_header, response.headers[location_header]))

        log.info("---------------------------------------------------------------")
        return response
    except Exception as ex:
        log.warning(ex)


def get_token():
    log.info("Generating token ...")
    HTTP_VERB = "POST"
    endpoint = "{}{}".format(config['TOKEN']['HOST_DNS'], config['TOKEN']['RESOURCE_NAME'])
    payload = {'grant_type': config['TOKEN']['GRANT_TYPE'],
               'client_id': config['SUBSCRIPTION']['CLIENT_ID'],
               'client_secret': config['SUBSCRIPTION']['CLIENT_SECRET']}
    response = do_request(HTTP_VERB, endpoint, payload, None, True, False)
    token = response.json()["access_token"]
    return f"{config['TOKEN']['AUTH_TYPE']} {token}"


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(asctime)s -> %(message)s')
    log = logging.getLogger('client')

    # Configure properties data
    config = configparser.ConfigParser()
    config.sections()
    config.read('resources/data.ini')

    # Building API request
    headers = {
        'Authorization': get_token(),
        'B-Application': config['SUBSCRIPTION']['B_APPLICATION'],
        'B-Transaction': config['REQUEST']['B_TRANSACTION'],
        'B-Option': config['REQUEST']['B_OPTION'],
        'Content-Type': config['REQUEST']['MIME_TYPE'],
        'Accept-Charset': config['REQUEST']['ENCODE_CHARSET'],
        'Accept': config['REQUEST']['MIME_TYPE']
    }
    api_endpoint = "{}{}{}".format(config['API']['HOST_DNS'], config['API']['BASE_PATH'],
                                   config['API']['RESOURCE_NAME'])
    do_request(config['REQUEST']['HTTP_VERB'], api_endpoint, config['REQUEST']['UNENCRYPTED_PAYLOAD'], headers, config['REQUEST']['SEND_PAYLOAD'], True)
