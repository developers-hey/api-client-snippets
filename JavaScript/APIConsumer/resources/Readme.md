# Description `Spanish translation:` Descripción

This Documentation provides classes to help consume Banking as a Service (BaaS) APIs in a secure manner. These classes implement security best practices to ensure that user data is protected. `Spanish translation:` Esta documentación proporciona clases para ayudar a consumir las API de Banking as a Service (BaaS) de forma segura. Estas clases implementan las mejores prácticas de seguridad para garantizar la protección de los datos de los usuarios.

### Prerequisites `Spanish translation:`  Requisitos previos 

The authentication credentials required to access the BaaS API must have been created. `Spanish translation:`  Se deben haber creado las credenciales de autenticación necesarias para acceder a la API de BaaS. 

## Create .env file `Spanish translation:` Crear un archivo .env
This file reads the private and public key paths and the application ID. The .env file should have the following structure. `Spanish translation:` Este archivo lee las rutas de las claves privada y pública y el id de la aplicación. El archivo .env debe tener la siguiente estructura.

1. CERT_PATH: This key specifies the path to the mTLS certificate file in the APIConsumer project. `Spanish translation:` Esta clave especifica la ruta al archivo del certificado mTLS en el proyecto APIConsumer.
2. PRIVATE_KEY_PATH: This key specifies the path to the client private key file in the APIConsumer project. `Spanish translation:` Esta clave especifica la ruta al archivo de la clave privada del cliente en el proyecto APIConsumer. 
3. PUBLIC_KEY_PATH: This key specifies the path to the server public key file in the APIConsumer project. `Spanish translation:` Esta clave especifica la ruta al archivo de clave pública del servidor en el proyecto APIConsumer. 
4. HOSTNAME: Defines the hostname of the remote server. `Spanish translation:` Define el hostname del servidor remoto.
5. OAUTH_CLIENT_ID: The client ID used to authenticate with the remote server. `Spanish translation:` El ID de cliente utilizado para autenticarse con el servidor remoto.
6. OAUTH_CLIENT_SECRET: The client secret used to authenticate with the remote server. `Spanish translation:` La clave secreta del cliente utilizada para autenticarse con el servidor remoto.
7. B_APPLICATION: Unique consumer application identifier, used to sign and encrypt the payload. `Spanish translation:`  Identificador único de la aplicación del consumidor, utilizado para firmar y cifrar el payload.



## Create PEM Certificates  `Spanish translation:` Creación de certificados PEM

Extract the security kit in the path, it is recommended to use the resources path of this project. Then run the following commands to convert the certificates sent to pem.  `Spanish translation:` Extraiga el kit de seguridad en la ruta, se recomienda utilizar la ruta de recursos de este proyecto. A continuación, ejecute los siguientes comandos para convertir los certificados enviados a pem.

```openssl

  openssl pkcs12 -in Client_KeyStore_test_16723f8c-e2a6-4dd3-a663-572c4a255e69.p12  -nokeys -out cert.pem
  openssl rsa -passin pass:Password -in Client_test_16723f8c-e2a6-4dd3-a663-572c4a255e69.key > Client_test_16723f8c-e2a6-4dd3-a663-572c4a255e69.pem
  ```

## Module SecurityManager `Spanish translation:` Módulo SecurityManager
This module provides methods for signing and encrypting payloads, and decrypting and verifying signed payloads. `Spanish translation:` Este módulo proporciona métodos para firmar y cifrar payloads, y descifrar y verificar payloads firmados.


The module makes use of the following libraries.  `Spanish translation:` El módulo hace uso de las siguientes bibliotecas.

```javascript
npm install jose
npm install fs
npm install rsa-pem-to-jwk
npm install dotenv
```

# Usage `Spanish translation:` Uso

Step 1: Load the keys. `Spanish translation:` Paso 1: Cargar las claves.
To sign and encrypt a payload, you must first load the private and public keys in PEM format and set them as JWK objects. This is done using the loadKeys function.  It also declares the constants to be used in the module. `Spanish translation:` Para firmar y cifrar el payload, primero debes cargar las claves privada y pública en formato PEM y establecerlas como objetos JWK. Esto se hace utilizando la función loadKeys.  También declara las constantes que se utilizarán en el módulo.
```javascript
  
const algorithm = 'RSA'
const alg = 'RS256'
const format = 'utf8'
const EncryptionMethod = 'A256GCM'
const JWEAlgorithm = 'RSA-OAEP-256'

function loadKeys() {
    privatePem = fs.readFileSync(process.env.PRIVATE_KEY_PATH, format);
    jwkPrivateRSA = rsaPemToJwk(privatePem, { kid: process.env.B_APPLICATION }, 'private');
    publicPem = fs.readFileSync(process.env.PUBLIC_KEY_PATH, format);
}
```


Step 2: Creates the function to sign and encrypt the payload. `Spanish translation:` Paso 2: Crea la función para firmar y encriptar el payload.

To sign and encrypt a payload, use the signAndEncryptPayload(requestPayload) function. This function takes the payload to be signed and encrypted as an argument and returns the signed and encrypted payload as a string. `Spanish translation:` Para firmar y cifrar el payload, utilice la función signAndEncryptPayload(requestPayload). Esta función toma el payload que se va a firmar y cifrar como argumento y devuelve el payload firmado y cifrado como una cadena.

```javascript
async function signAndEncryptPayload(requestPayload) {
    loadKeys();
    publicKey = await jose.importSPKI(publicPem, algorithm);
    privateKey = await jose.importJWK(jwkPrivateRSA, alg);

    const jsonPayload = JSON.parse(requestPayload);
    const strSigned = await new jose.SignJWT(jsonPayload)
        .setProtectedHeader({ alg })
        .sign(privateKey);

    const strEncrypt = await new jose.CompactEncrypt(
        new TextEncoder().encode(strSigned),
    )
        .setProtectedHeader({ alg: JWEAlgorithm, enc: EncryptionMethod, kid: process.env.B_APPLICATION })
        .encrypt(publicKey)
    return strEncrypt
}

```
Step 3: Create the function to decrypt and verify the signed payload. `Spanish translation:` Paso 3: Crea la función para descifrar y verificar la carga firmada.

To decrypt and verify the signature of a JWE/JWS payload, use the decryptAndVerifySignPayload(responsePayload) function. This function takes the JWE/JWS payload to be decrypted and verified as an argument and returns the decrypted and verified payload as a string. `Spanish translation:` Para descifrar y verificar la firma de un payload JWE/JWS, utilice la función decryptAndVerifySignPayload(responsePayload). Esta función toma el payload JWE/JWS que debe descifrarse y verificarse como argumento y devuelve el payload descifrado y verificado como cadena.
```javascript
async function decryptAndVerifySignPayload(responsePayload) {
    loadKeys();
    publicKey = await jose.importSPKI(publicPem, algorithm);
    privateKey = await jose.importJWK(jwkPrivateRSA, alg);
    const { plaintext } = await jose.compactDecrypt(responsePayload, privateKey);
    const strDecrypt = new TextDecoder().decode(plaintext);
    const { payload } = await jose.compactVerify(strDecrypt, publicKey);
    return new TextDecoder().decode(payload);
}

```
Step 4:  Export the created funcions. `Spanish translation:` Paso 3: Exporta las funciónes creadas.
```javascript
module.exports =
{
    signAndEncryptPayload,
    decryptAndVerifySignPayload
}
```


# APIClient Module  `Spanish translation:` Módulo APIClient

## Description  `Spanish translation:` Descripción
This module exports the APIClient class, which provides a simple way to make HTTP requests to an API using OAuth 2.0 authentication with client credentials grant flow and encrypted payloads. `Spanish translation:` Este módulo exporta la clase APIClient, que proporciona una forma sencilla de realizar peticiones HTTP a una API utilizando autenticación OAuth 2.0 con flujo de concesión de credenciales de cliente y payloads cifrados.


# Usage `Spanish translation:` Uso

Step 1: Create ApiClient and declare attributes. `Spanish translation:`  Crear el ApiClient y declarar atributos.

Create the ApiClient class where the SecurityManager class is defined. Then, declare the following attributes. `Spanish translation:` Cree la clase ApiClient donde se define la clase SecurityManager. Luego, declare los siguientes atributos.

 Las constantes **CERT_PATH** y **PRIVATE_KEY_PATH** representan las rutas al archivo del certificado y al archivo de la clave privada. 
```javascript
const CERT = fs.readFileSync(process.env.CERT_PATH);
const PRIVATE_KEY = fs.readFileSync(process.env.PRIVATE_KEY_PATH);
const TOKEN_ENDPOINT = '/auth/v1/oidc/token'
const HTTP_METHOD = 'POST';
const HEADER_KEY = 'Content-Type';
const HEADER_VALUE = 'application/x-www-form-urlencoded';
const OAUTH_GRANT_TYPE_VALUE = 'client_credentials';
```

### 1.1 Create an ApiClient constructor object with the specified parameters. `Spanish translation:` Crea un constructor ApiClient con los parámetros.

```javascript
  constructor() {
    this.basePath = '/taas/v1.0';
    this.clientId = process.env.OAUTH_CLIENT_ID;
    this.clientSecret = process.env.OAUTH_CLIENT_SECRET;
    this.accessToken = null;
  }
```
Step 2 Creates getAuthorizationToken method. `Spanish translation:` Paso 2 Crea el método getAuthorizationToken.
Generates an authorization token using client credentials grant type. This method makes a POST request to a specified token URL with the client ID and client secret. `Spanish translation:` Genera un token de autorización utilizando el tipo de concesión de credenciales de cliente. Este método realiza una solicitud POST a una URL de token especificada con el ID de cliente y la clave secreta de cliente.
```javascript
  getAuthorizationToken() {
    const options = {
      url: process.env.HOSTNAME + TOKEN_ENDPOINT,
      method: HTTP_METHOD,
      headers: {
        'Content-Type': HEADER_VALUE,
      },
      form: {
        grant_type: OAUTH_GRANT_TYPE_VALUE,
        client_id: this.clientId,
        client_secret: this.clientSecret,
      }, agentOptions: {
        key: PRIVATE_KEY,
        cert: CERT,
      },
    };

    return new Promise((resolve, reject) => {
      request(options, (error, response, body) => {
        if (error) {
          reject(error);
        } else {
          const data = JSON.parse(body);
          this.accessToken = data.access_token;
          resolve(data.access_token);
        }
      });
    });
  }


```
Step 3: Creates the makeRequest method. `Spanish translation:` Crea el método makeRequest.

Makes a request to the API using the provided parameters and access token. The body of the request is signed and encrypted before being sent, and the data is returned in JSON format. It returns a promise that resolves to the request response. `Spanish translation:` Realiza una solicitud a la API utilizando los parámetros y el token de acceso proporcionados. El cuerpo de la solicitud se firma y encripta antes de enviarse, y los datos se devuelven en formato JSON. Devuelve una promesa que resuelve la respuesta a la solicitud.

```javascript
 async makeRequest(endpoint, method = 'POST', body = null, headers) {
    if (!this.accessToken) {
      await this.getAuthorizationToken();
    }
    let signedEncryptedPayloadJson = null;
    if (body) {
      const signedEncryptedPayload = await securityManager.signAndEncryptPayload(body);
      signedEncryptedPayloadJson = { data: signedEncryptedPayload }
    }

    const options = {
      url: process.env.HOSTNAME + `${this.basePath}${endpoint}`,
      method,
      headers: {
        Accept: headers.Accept,
        'Content-Type': headers.Content_Type,
        'B-Transaction': headers.B_Transaction,
        'Accept-Charset': headers.Accept_Charset,
        'B-application': process.env.B_APPLICATION,
        Authorization: `Bearer ${this.accessToken}`,
      }, agentOptions: {
        key: PRIVATE_KEY,
        cert: CERT,
      },
      json: signedEncryptedPayloadJson ? signedEncryptedPayloadJson : true,
    };

    return new Promise((resolve, reject) => {
      request(options, (error, response, body) => {
        if (error) {
          reject(error);
        } else {
          resolve(response);
        }
      });
    });
  }

```
## Example implementation of an API client.  ` Spanish translation:` Ejemplo de implementación de un cliente API.

 Example of an API client implementation using the modules described in the previous steps. ` Spanish translation:` Ejemplo de implementación de un cliente API utilizando los módulos descritos en los pasos anteriores.

To use the functions provided by this module, you need to import it into your code as follows. ` Spanish translation:`  Para utilizar las funciones proporcionadas por este módulo, debe importarlo en su código de la siguiente manera.
```javascript
const request = require('request');
const securityManager = require('./SecurityManager.js');
const dotenv = require('dotenv');
const fs = require('fs');
dotenv.config();

```
Step 1: Creates an instance of the APIClient client, which will be used to make requests to a server. ` Spanish translation:` Paso 1: Crea una instancia del cliente APIClient, que se utilizará para realizar solicitudes a un servidor.

```javascript
const client = new APIClient();
```

 Step 2: Creates the endpoint, HTTP method and payload to be sent with the request. ` Spanish translation:` Paso 2: Crea el endpoint, el método HTTP y el payload que se enviará con la solicitud. 
 ```javascript
const endpoint = '/accounts';
const http_method = 'POST';
const requestPayload = `{"taxRegimeId": 2,"name": "Jose Luis","lastName": "Lemus","secondLastName": "Valdivia","businessName": "","birthday": "1996-10-03","rfc": "LEVL961003KQ0","curp": "LEVL961003HBSMLS06","callingCode": "52","cellPhoneNumber": "3311065681","email": "jose.lemus@banregio.com","nationalityId": "001","countryId": "01","stateId": "047","cityId": "04701005","legalRepresentative": {"name": "","lastName": "","secondLastName": ""}}`;
 ```
Step 3: Creates the application headers. ` Spanish translation:` Paso 3: Crea las cabeceras de la aplicación.
 ```javascript
const headers = {
  'Accept': 'application/json',
  'Content_Type': 'application/json',
  'B_Transaction': '12345678',
  'Accept_Charset': 'UTF-8'
};
 ```

Step 4: Obtain authorization token. ` Spanish translation:` Paso 4: Obtener el token de autorización.
 ```javascript
client.getAuthorizationToken().then((accessToken) => {
  
}).catch((error) => {
  console.error(error);
});
 ```
Step 5: Make the API request with the signed and encrypted payload, in addition print the response. ` Spanish translation:` Paso 5: Realizar la petición API con el payload firmado y encriptado, además imprima la respuesta.
 ```javascript
client.getAuthorizationToken().then((accessToken) => {
  client.makeRequest(endpoint, http_method, requestPayload, headers)
    .then((response) => {
      console.log(response.headers);
      console.log(response.body);
   
    })
    .catch((error) => {
      console.error(error);
    });
}).catch((error) => {
  console.error(error);
});
 ```
Step 6: Make another API request to get the encrypted response. ` Spanish translation:` Paso 6: Realice otra solicitud API para obtener la respuesta cifrada.
```javascript
client.getAuthorizationToken().then((accessToken) => {
  client.makeRequest(endpoint, http_method, requestPayload, headers)
    .then((response) => {
      console.log(response.headers);
      console.log(response.body);
      if (response.headers.location) {
        const headers = {
          'Accept': 'application/json',
          'B_Transaction': '12345678',
          'Accept_Charset': 'UTF-8'
        };
        client.makeRequest(response.headers.location, 'GET', null, headers)
          .then(async (response) => {
            console.log(response.headers);
            console.log(response.body);
          })
          .catch((error) => {
            console.error(error);
          });
      }
    })
    .catch((error) => {
      console.error(error);
    });
}).catch((error) => {
  console.error(error);
});
 ```
Step 7: If the encrypted response body is not empty, decrypt and verify the signed payload. ` Spanish translation:` Paso 7: Si el cuerpo de la respuesta cifrada no está vacío, descifre y verifique el archivo firmado.
```javascript
client.getAuthorizationToken().then((accessToken) => {
  client.makeRequest(endpoint, http_method, requestPayload, headers)
    .then((response) => {
      console.log(response.headers);
      console.log(response.body);
      if (response.headers.location) {
        const headers = {
          'Accept': 'application/json',
          'B_Transaction': '12345678',
          'Accept_Charset': 'UTF-8'
        };
        client.makeRequest(response.headers.location, 'GET', null, headers)
          .then(async (response) => {
            console.log(response.headers);
            console.log(response.body);
            if (response.body.data) {
              const decryptedVerifiedPayload = await securityManager.decryptAndVerifySignPayload(response.body.data);
              console.log(decryptedVerifiedPayload);
            }

          })
          .catch((error) => {
            console.error(error);
          });
      }
    })
    .catch((error) => {
      console.error(error);
    });
}).catch((error) => {
  console.error(error);
});
 ```
