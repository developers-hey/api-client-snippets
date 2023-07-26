# Java Snippet `Spanish translation:` Fragmento de Java
This Documentation provides classes to help consume Banking as a Service (BaaS) APIs in a secure manner. `Spanish translation:` Esta documentación proporciona clases para ayudar a consumir las API de Banking as a Service (BaaS) de forma segura. 

### Prerequisites `Spanish translation:` Requisitos previos 

* The authentication credentials required to access the BaaS API must have been created. `Spanish translation:` Se deben haber creado las credenciales de autenticación necesarias para acceder a la API de BaaS. 
* Java Development Kit (JDK) version 11 `Spanish translation:` Versión 11 de Java Development Kit (JDK).
* Gradle version 7.6.1 `Spanish translation:` Version de Gradle 7.6.1
* Review and install the archive libraries requirements.txt Spanish translation: Revisar e instalar las librerias del archivo requirements.txt

### Create PEM Certificates  `Spanish translation:` Creación de certificados PEM

Extract the security kit in the path, it is recommended to use the resources path of this project. Then run the following commands to convert the certificates sent to pem.  `Spanish translation:` Extraiga el kit de seguridad en la ruta, se recomienda utilizar la ruta de recursos de este proyecto. A continuación, ejecute los siguientes comandos para convertir los certificados enviados a pem.

```openssl

  openssl rsa -passin pass:Password -in Client_sbox.key > Client_sbox.pem
  ```
## Configure the config.properties file `Spanish translation:` Configurar el archivo config.properties

* CLIENT.ID: The client ID used to authenticate with the remote server. `Spanish translation:` El ID de cliente utilizado para autenticarse con el servidor remoto. 
* CLIENT.SECRET: The client secret used to authenticate with the remote server. `Spanish translation:` La clave secreta del cliente utilizada para autenticarse con el servidor remoto.
* B.APPLICATION: Unique consumer application identifier, used to sign and encrypt the payload. `Spanish translation:` Identificador único de la aplicación del consumidor, utilizado para firmar y cifrar el payload.
* HOSTNAME.DNS : Defines the hostname of the remote server, example:https://sbox-api-tech.hey.inc. `Spanish translation:` Define el hostname del servidor remoto,  ejemplo:https://sbox-api-tech.hey.inc.
* KEYSTORE.PATH: This key specifies the path to the client keystore file (.p12). `Spanish translation:` Esta clave especifica la ruta al archivo del almacén de claves (.p12) del cliente.
* KEYSTORE.PASSWORD: This key specifies the password for the client keystore file. `Spanish translation:` Esta clave especifica la contraseña para el archivo keystore del cliente. 
* PRIVATEKEY: This key specifies the path to the client private key file in the APIClient project. `Spanish translation:` Esta clave especifica la ruta al archivo de clave privada del cliente en el proyecto APIClient.
* SERVER.PUBLICKEY: This key specifies the path to the server public key file in the APIClient project. `Spanish translation:` Esta clave especifica la ruta al archivo de clave pública del servidor en el proyecto APIClient.
* BASE.PATH: API base path, example:/taas/v1.0.  `Spanish translation:` Ruta base del API, ejemplo /taas/v1.0.
* URI.NAME: Endpoint URI name. `Spanish translation:` Nombre del URI del endpoint.
* OAUTH.URI.NAME: Name of the URI to obtain OAuth token. `Spanish translation:` Nombre del URI para obtener el token OAuth.
* OAUTH.GRANT.TYPE: Grant type used for authentication. `Spanish translation:` Tipo de concesión (grant type) utilizado para la autenticación.
* HTTP.VERB: HTTP verb used for the request (e.g. GET, POST, PUT, DELETE). `Spanish translation:` Verbo HTTP utilizado para la solicitud (por ejemplo, GET, POST, PUT, DELETE).
* UNENCRYPTED.PAYLOAD: Payload without encryption. `Spanish translation:` Carga útil sin cifrar.
* B.TRANSACTION: Transaction ID in the API consumer's `Spanish translation:` Identificador de la transacción en la aplicación del consumidor de la API.
* B.OPTION: Request option to indicate, for example, a specific type of update with the PATCH method. `Spanish translation:` Opción de la petición para indicar por ejemplo un tipo específico de actualización con el método PATCH.
* MIME.TYPE: Media type (MIME) of the content (e.g. "application/json"). `Spanish translation:` Tipo de medio (MIME) del contenido (por ejemplo, "application/json").
* ENCODE.CHARSET: Encoding character set (e.g. "UTF-8"). `Spanish translation:`  Conjunto de caracteres de codificación (por ejemplo, "UTF-8").

## Development/Test `Spanish translation:` Desarrollo/Pruebas ⚙️

Executes the Client.java class that contains the main method. `Spanish translation:` Ejecuta la clase Client.java que contiene el método main.
### During execution, the snippet will perform the following operations: `Spanish translation:` Durante la ejecución, el snippet realizará las siguientes operaciones:
1. It will load the properties from the config.properties file. `Spanish translation:` Cargará las propiedades desde el archivo config.properties.
2. Obtain the authorization token using the securityManager. `Spanish translation:` Obtendrá el token de autorización utilizando el securityManager.
3. Build the headers for the HTTP request with the configured properties. `Spanish translation:` Construirá los encabezados para la solicitud HTTP con las propiedades configuradas.
4. Sign and encrypt the payload using the securityManager. `Spanish translation:` Firmará y cifrará la carga útil utilizando el securityManager.
5. Make an HTTP request to the specified endpoint. `Spanish translation:` Realizará una solicitud HTTP al endpoint especificado.
6. Display the headers and the body of the response. `Spanish translation:` Mostrará los encabezados y el cuerpo de la respuesta.
7. If there is a response with location header, make another GET request to that location. `Spanish translation:` Si hay una respuesta con encabezado location, realizará otra solicitud GET a ese location.
8. It will display the body of the encrypted and decrypted response. `Spanish translation:` Mostrará el cuerpo de la respuesta encriptado y descifrado. 
