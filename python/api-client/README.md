# Description `Spanish translation:` Descripción

This documentation provides python files for consuming Banking as a Service (BaaS) APIs securely. `Spanish translation:` Esta documentación proporciona archivos python para el consumo de las API de Banking as a Service (BaaS) de forma segura.

### Prerequisites `Spanish translation:` Requisitos previos 

The authentication credentials required to access the BaaS API must have been created. `Spanish translation:` Se deben haber creado las credenciales de autenticación necesarias para acceder a la API de BaaS. 

Consider and install the following libraries. `Spanish translation:` Considerar e instalar las siguientes librerias:
* cepmex==0.2.1
* certifi==2023.5.7
* charset-normalizer==2.0.12
* clabe==1.2.9
* idna==3.4
* lxml==4.9.2
* pydantic==1.10.8
* requests==2.26.0
* typing_extensions==4.6.2
* urllib3==1.26.16
* pyopenssl==23.2.0
* cryptography~=41.0.1
* Authlib~=1.2.0

### Configure file data.ini `Spanish translation:` Configurar archivo data.ini
* client.id: The client ID used to authenticate with the remote server. `Spanish translation:` El ID de cliente utilizado para autenticarse con el servidor remoto. 
* client.secret: The client secret used to authenticate with the remote server. `Spanish translation:` La clave secreta del cliente utilizada para autenticarse con el servidor remoto.
* b.application: Identifier to know which application consumes said API, used to sign and encrypt the payload. `Spanish translation:` Identificador para saber que aplicación consume dicha API, utilizado para firmar y cifrar el payload.
* host.dns: Defines the hostname of the remote server. `Spanish translation:` Define el hostname del servidor remoto
* base.path: Endpoint base URI.  `Spanish translation:` URI base.
* uri.name: Endpoint name. `Spanish translation:` Nombre del endpoint
* grant.type: default value grant_type. `Spanish translation:` El valor default es grant_type. `
* auth.type: The token must be of type Bearer. `Spanish translation:` El tipo de token debe ser Bearer.
* p12.path: Keystore that stores client's public certificate and its private key used to be identified by the API in the handshake process. Also used to decrypt the response payload.. `Spanish translation:` Almacén de claves que almacena el certificado público del cliente y su clave privada solía ser identificado por la API en el proceso de negociación. También se usa para descifrar la carga de respuesta.
* p12.passwd: This key specifies the password for the client keystore file. `Spanish translation:` Esta clave especifica la contraseña para el archivo keystore del cliente.
* server.publickey: Public key of the server used to encrypt the request and validate the signature on the response. `Spanish translation:` Clave pública del servidor utilizada para cifrar la solicitud y validar la firma en la respuesta.
* http.verb: Endpoint http verb. `Spanish translation:` punto final http verbo.
* unencrypted.payload: Clear request to send. `Spanish translation:` Petición en claro a mandar
* b.transaction: Transaction ID in the API consumer's `Spanish translation:` Identificador de la transacción en la aplicación del consumidor de la API.
* b.option: Request option to indicate, for example, a specific type of update with the PATCH method. `Spanish translation:` Opción de la petición para indicar por ejemplo un tipo específico de actualización con el método PATCH.
* mime.type: Content-Type indicates to the client what type of content the resource will return. `Spanish translation:` Content-Type indica al cliente qué tipo de contenido devolvera el recurso.
* encode.charset:(UTF-8) character encoding format capable of representing any Unicode character. `Spanish translation:` Formato de codificación de caracteres capaz de representar cualquier carácter Unicode.

### Usage `Spanish translation:` Uso

### Step 1: Generate a token with the data preloaded in the data.ini file. `Spanish translation:` Paso 1: Generar un token con los datos pre cargados en el archivo data.ini.

```python
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

```

### Step 2: Headers are built. `Spanish translation:` Paso 2: Se construye las cabeceras.

```python
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

```

### Step 3: The request is executed  `Spanish translation:` Paso 3: Se ejecuta la petición.

```python
    api_endpoint = "{}{}{}".format(config['api']['host.dns'], config['api']['base.path'], config['api']['uri.name'])
    do_request(config['request']['http.verb'], api_endpoint, config['request']['unencrypted.payload'], headers, True)

```

### Step 4: Creates the method to sign and encrypt the payload. `Spanish translation:` Paso 4: Crea el método para firmar y encriptar el payload.
```python
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
```

Step 5: Create the method  to decrypt and verify the signed payload. `Spanish translation:` Paso 5: Crea el método para descifrar y verificar el payload firmado.
```python
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
```



