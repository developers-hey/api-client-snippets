# API Client Snippets / Fragmentos de Cliente API 

> This repository contains REST API client snippets to consume Hey Banco and Banregio API's using the most common programming languages. `Spanish translation:` Este repositorio contiene fragmentos de cliente de API REST para consumir las API de Hey Banco y Banregio utilizando los lenguajes de programación más comunes:
> 1. Java
> 2. JavaScript(NodeJs)
> 3. Python
> 4. .NET
> 
---


## Requisites / Requisitos 📋

1. Depending of programming language that you going to select to consume an API, you need one of the followings compiler or interpreter and a package manager. `Spanish translation:` Dependiendo del lenguaje de programación que vayas a seleccionar para consumir una API, necesitarás uno de los siguientes compiladores o intérpretes y un administrador de paquetes.

| Language / Lenguaje                   |    Libraries / Librerías     | Directory / Directorio      |
|:------------------------------------: |:-----------------------------|:----------------------------|
| [Java](/Java/APIClient)               | JDK 11 or +, Gradle          | /Java/APIClient             |
| [JavaScript](/JavaScript/api-client)  | NodeJS 18 or +, NPM          | /JavaScript/api-client      |
| [Python](/Python/api-client)          | Python 3 or +, pip           | /Python/api-client          |
| [.NET](Net/APIClient/)                | net7.0 or +                  | /Net/APIClient/             |



2. Unzip your **API Kit** files that contains SSL certificates and credentials as following describe. `Spanish translation:` Descomprime tus archivos de API kit que contiene certificados SSL y credenciales como se describe a continuación:

| Folder / Carpeta                      |    File / Archivo            | Content / Contenido                                 |
|:------------------------------------- |:-----------------------------|:----------------------------------------------------|
| `Client_Credentials_{API-product}_{Environment}.zip`  | **Consumer.txt**               | The app identifier of the API consumer (B-Application). `Spanish translation:` El identificador de aplicación del consumidor de API (B-Application). |
| `Client_Credentials_{API-product}_{Environment}.zip`  | **Token.txt**                  | Credentials to get the JWT token used to consume the API. `Spanish translation:` Credenciales para obtener el token JWT utilizado para consumir la API. |
| `Client_Certificates_{API-product}_{Environment}.zip`  | **Client_Passwd.txt**          | Password for KeyStore, TrustStore and PrivateKey files. `Spanish translation:` Contraseña para archivos KeyStore, TrustStore y PrivateKey. |
| `Client_Certificates_{API-product}_{Environment}.zip`  | **Client_KeyStore_mTLS.p12**   | List of client private keys to establish a mutual TLS connection with each API. `Spanish translation:` Lista de llaves privadas del cliente para establecer una conexión TLS mutua con cada API. |
| `Client_Certificates_{API-product}_{Environment}.zip`  | **Server_PublicKey_JWE.pem**   | Server public key to encrypt API requests payloads using JWE and JWS standards. `Spanish translation:` Clave pública del servidor para encriptar los payload de petición a la API utilizando los estándares JWE y JWS.           |

---
 

## Setup 🛠️

|Group / Grupo  | Property / Propiedad      | Description / Descripción                                         |
|:--------------|:--------------------------|:------------------------------------------------------------------|
|`SUBSCRIPTION` | **B_APPLICATION**         | The app identifier of the API consumer (B-Application) in UUID format. `Spanish translation:` El identificador de aplicación del consumidor de API (B-Application) en formato UUID.       |
|`SUBSCRIPTION` | **CLIENT_ID**             | The client ID used to get the JWT token used to consume the API. `Spanish translation:` El ID de cliente utilizado para obtener el token JWT utilizado para consumir la API.       |
|`SUBSCRIPTION` | **CLIENT_SECRET**         | The client secret used to get the JWT token used to consume the API. `Spanish translation:` La clave secreta del cliente utilizada para obtener el token JWT utilizado para consumir la API.       |
|`API`          | **HOST_DNS**              | Defines the hostname or DNS of the API server. `Spanish translation:` Define el hostname o DNS del servidor de la API.       |
|`API`          | **BASE_PATH**             | API URI base path (context).  `Spanish translation:` Ruta base (contexto) de la URI de la API.       |
|`API`          | **RESOURCE_NAME**         | API resource path. `Spanish translation:` Ruta del recurso de la API.      |
|`TOKEN`        | **HOST_DNS**              | Defines the hostname or DNS of the authorization server. `Spanish translation:` Define el hostname o DNS del servidor de autorización.       |
|`TOKEN`        | **RESOURCE_NAME**         | Name of the resource to obtain a JWT token. `Spanish translation:` Nombre del recurso para obtener un token JWT.       |
|`TOKEN`        | **GRANT_TYPE**            | Grant type used for authentication. `Spanish translation:` Tipo de concesión (grant type) utilizado para la autenticación.       |
|`TOKEN`        | **AUTH_TYPE**             | Token schema. `Spanish translation:` Esquema del token.       |
|`MTLS`         | **KEYSTORE_PATH**              | Path to keystore file (.p12). `Spanish translation:` Ruta del archivo almacén de certificados (.p12).       |
|`MTLS`         | **KEYSTORE_PASSWD**            | Specifies the password for the keystore file (.p12). `Spanish translation:` Especifica la contraseña para el archivo almacen de certificados (.p12).       |
|`JWE`          | **SERVER_PUBLICKEY**      | Specifies the path to the server public key file (certificate). `Spanish translation:` Especifica la ruta al archivo de clave pública del servidor (certificado).       |
|`REQUEST`      | **HTTP_VERB**             | HTTP verb used for the request (e.g. GET, POST, PUT, DELETE). `Spanish translation:` Verbo HTTP utilizado para la petición (por ejemplo, GET, POST, PUT, DELETE).       |
|`REQUEST`      | **SEND_PAYLOAD**          | Flag to indicate if the request must to include the body. `Spanish translation:` Bandera para indicar si la solicitud debe incluir el body.       |
|`REQUEST`      | **UNENCRYPTED_PAYLOAD**   | Request payload without encryption. `Spanish translation:` Payload de la petición sin cifrar.       |
|`REQUEST`      | **B_TRANSACTION**         | Transaction ID in the API consumer's system. `Spanish translation:` Identificador de la transacción en el sistema del consumidor de la API.       |
|`REQUEST`      | **B_OPTION**              | Request option to indicate, for example, a specific type of update with the PATCH method. `Spanish translation:` Opción de la petición para indicar por ejemplo, un tipo específico de actualización con el método PATCH.       |
|`REQUEST`      | **MIME_TYPE**             | Media type (MIME) of the content (e.g. "application/json"). `Spanish translation:` Tipo de medio (MIME) del contenido (por ejemplo, "application/json").       |
|`REQUEST`      | **ENCODE_CHARSET**        | Encoding character (e.g. "UTF-8"). `Spanish translation:`  Codificación de caracteres (por ejemplo, "UTF-8").       |


---


##  Testing ⚙️

* Java
```bash
cd Java/APIClient
./gradlew run
```

* Python
```bash
cd Python/api-client
pip install -r requirements.txt
python client.py
```

* NodeJS
```bash
cd JavaScript/api-client
npm install
npm start
```

* .NET
```bash
cd Net/APIClient

```

---


### Autors / Autores ✒️
- [Hey, Tech developers](mailto:developers@hey.inc?subject=API%20Snippets)


### Notes / Notas 📄

* To consume the API is needed internet connection reaching out the followings DNS: `Spanish translation:` Para consumir la API se necesita conexión a internet llegando a los siguientes DNS:

  * Hey Banco
    *  Token(Sandbox): https://sbox-api-tech.hey.inc/auth/v1/oidc/token
    *  API(Sandbox): https://sbox-api-tech.hey.inc/{api-product}/{api-version}/{api}
    *  Token(Live): https://api-tech.hey.inc/auth/v1/oidc/token
    *  API(Live): https://api-tech.hey.inc/{api-product}/{api-version}/{api}


  * Banregio
    *  Token(Sandbox): https://sbox-open-api.banregio.com/auth/v1/oidc/token
    *  API(Sandbox): https://sbox-open-api.banregio.com/{api-product}/{api-version}/{api}
    *  Token(Live): https://open-api.banregio.com/auth/v1/oidc/token
    *  API(Live): https://open-api.banregio.com/{api-product}/{api-version}/{api}

