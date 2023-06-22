# Python Snippet `Spanish translation:` Fragmento de Python

This documentation provides python files for consuming Banking as a Service (BaaS) APIs securely. `Spanish translation:` Esta documentación proporciona archivos python para el consumo de las API de Banking as a Service (BaaS) de forma segura.

## Prerequisites `Spanish translation:` Requisitos previos 

* The authentication credentials required to access the BaaS API must have been created. `Spanish translation:` Se deben haber creado las credenciales de autenticación necesarias para acceder a la API de BaaS. 
* Python version 3.11.0 `Spanish translation:` versión de python 3.11.0
* Review and install the archive libraries **requirements.txt** `Spanish translation:` Revisar e instalar las librerias del archivo **requirements.txt**

## Configure file data.ini `Spanish translation:` Configurar archivo data.ini
* client.id: The client ID used to generate the token. `Spanish translation:` El ID de cliente utilizado para generar el token. 
* client.secret: The client secret key to generate the token. `Spanish translation:` La clave secreta del cliente para generar el token.
* b.application: Identifier to know which application consumes said API, used to sign and encrypt the payload. `Spanish translation:` Identificador para saber que aplicación consume dicha API, utilizado para firmar y cifrar el payload.
* host.dns: Defines the hostname of the remote server, example:https://sbox-api-tech.hey.inc. `Spanish translation:` Define el hostname del servidor remoto, ejemplo:https://sbox-api-tech.hey.inc
* base.path: Endpoint base URI, example:/laas/v1.0.  `Spanish translation:` URI base, ejemplo /laas/v1.0.
* uri.name: Endpoint name, example:/credit-offers. `Spanish translation:` Nombre del endpoint, ejemplo:/credit-offers
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

## Development/Test `Spanish translation:` Desarrollo/Pruebas ⚙️

1. Everything starts from the file `Spanish translation:` Todo inicia desde el archivo **client.py**.
2. To test this code snippet you must execute the do_request() method found in the main function, this is in charge of making the request to the API. `Spanish translation:` Para probar este fragmento de codigo debes ejecutar el metodo do_request() que se encuentra en la función principal, este es el encargado de realizar la peticón al API.
3. In the **encription.py** file we have the sign_and_encrypt_payload() methods to encrypt our request and the decrypt_and_verify_sign_payload() function to decrypt the API response. `Spanish translation:` En el archivo **encription.py** tenemos los metodos sign_and_encrypt_payload() para encriptar nuestra peticion y la función decrypt_and_verify_sign_payload() para desencriptar la respuesta del API.
4. In the **certificate.py** file we have the methods read_private_key(), read_public_key() and convert_p12_to_pem() these are used for mTLS implementation. `Spanish translation:` En el archivo **certificate.py** tenemos los metodos read_private_key(), read_public_key() y convert_p12_to_pem() esto son usados para implementación del mTLS.



