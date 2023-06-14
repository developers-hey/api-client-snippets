import configparser
import logging
import tempfile

import requests

from util import encryption, certificate


def do_request(http_verb: str, endpoint: str, request_payload: str, headers: dict, payload_encryption: bool):
    log.info("Request {}: {}".format(http_verb, endpoint))
    success_response_200 = 200
    success_response_201 = 201
    b_trace_header = "B-Trace"
    location_header = "Location"

    client_private_key = tempfile.NamedTemporaryFile()
    client_public_key = tempfile.NamedTemporaryFile()
    certificate.convert_p12_to_pem(config['mtls']['p12.path'], config['mtls']['p12.passwd'], client_private_key,
                                   client_public_key)

    if payload_encryption:
        request_payload = encryption.sign_and_encrypt_payload(request_payload,
                                                              config['subscription']['b.application'],
                                                              client_private_key.name,
                                                              config['jwe']['server.publickey'])

    try:
        response = requests.request(
            http_verb,
            headers=headers,
            url=endpoint,
            data=request_payload,
            cert=(client_public_key.name, client_private_key.name))

        log.info("Response: {} {}".format(response.status_code, response.reason))
        if payload_encryption and response.status_code == success_response_200:
            log.info(response.json())
            response_payload = {"code": response.json()["code"], "message": response.json()["message"],
                                "data": encryption.decrypt_and_verify_sign_payload(response.json()["data"],
                                                                                   client_private_key.name,
                                                                                   config['jwe']['server.publickey'])}
            log.info(response_payload)
        else:
            log.info(response.json())

        # Print relevant headers, for example: Locations contains the resource ID that have been created with POST
        # requests
        if response.status_code == success_response_200 and b_trace_header in response.headers:
            log.info("Headers: [{}={}]".format(b_trace_header, response.headers[b_trace_header]))
        if response.status_code == success_response_201 and location_header in response.headers:
            log.info("Header: [{}={}]".format(location_header, response.headers[location_header]))

        return response
    except Exception as ex:
        log.warning(ex)


def get_token():
    log.info("Generating token ...")
    HTTP_VERB = "POST"
    token_endpoint = "{}{}".format(config['token']['host.dns'], config['token']['uri.name'])
    payload = {'grant_type': config['token']['grant.type'],
               'client_id': config['subscription']['client.id'],
               'client_secret': config['subscription']['client.secret']}
    response = do_request(HTTP_VERB, token_endpoint, payload, None, False)
    token = response.json()["access_token"]
    return f"{config['token']['auth.type']} {token}"


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
        'B-Application': config['subscription']['b.application'],
        'B-Transaction': config['request']['b.transaction'],
        'B-Option': config['request']['b.option'],
        'Content-Type': config['request']['mime.type'],
        'Accept-Charset': config['request']['encode.charset'],
        'Accept': config['request']['mime.type']
    }
    api_endpoint = "{}{}{}".format(config['api']['host.dns'], config['api']['base.path'], config['api']['uri.name'])
    do_request(config['request']['http.verb'], api_endpoint, config['request']['unencrypted.payload'], headers, True)
