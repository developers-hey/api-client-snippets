# Description `Spanish translation:` Descripción

This Documentation provides classes to help consume Banking as a Service (BaaS) APIs in a secure manner. These classes implement security best practices to ensure that user data is protected. `Spanish translation:` Esta documentación proporciona clases para ayudar a consumir las API de Banking as a Service (BaaS) de forma segura. Estas clases implementan las mejores prácticas de seguridad para garantizar la protección de los datos de los usuarios.

### Prerequisites `Spanish translation:` Requisitos previos 

The authentication credentials required to access the BaaS API must have been created. `Spanish translation:` Se deben haber creado las credenciales de autenticación necesarias para acceder a la API de BaaS. 

## Create config.properties file `Spanish translation:` Crear archivo config.properties

This file reads the private and public key paths and the application ID. The config.properties file should have the following structure. `Spanish translation:` Este archivo lee las rutas de las claves privada y pública y el id de la aplicación. El archivo config.properties debe tener la siguiente estructura.

1. KEYSTORE_PATH: This key specifies the path to the client keystore file in the APIConsumer project. `Spanish translation:` Esta clave especifica la ruta al archivo del almacén de claves del cliente en el proyecto APIConsumer.
2. KEYSTORE_PASSWORD: This key specifies the password for the client keystore file. `Spanish translation:` Esta clave especifica la contraseña para el archivo keystore del cliente. 
3. PRIVATEKEY: This key specifies the path to the client private key file in the APIConsumer project. `Spanish translation:` Esta clave especifica la ruta al archivo de clave privada del cliente en el proyecto APIConsumer.
4. PUBLICKEY: This key specifies the path to the server public key file in the APIConsumer project. `Spanish translation:` Esta clave especifica la ruta al archivo de clave pública del servidor en el proyecto APIConsumer.
5. HOSTNAME: Defines the hostname of the remote server. `Spanish translation:` Define el hostname del servidor remoto. 
6. OAUTH_CLIENT_ID: The client ID used to authenticate with the remote server. `Spanish translation:` El ID de cliente utilizado para autenticarse con el servidor remoto. 
7. OAUTH_CLIENT_SECRET: The client secret used to authenticate with the remote server. `Spanish translation:` La clave secreta del cliente utilizada para autenticarse con el servidor remoto.
8. B_APPLICATION: Unique consumer application identifier, used to sign and encrypt the payload. `Spanish translation:` Identificador único de la aplicación del consumidor, utilizado para firmar y cifrar el payload.

# Create the SecurityManager class `Spanish translation:` Crea la clase SecurityManager

The SecurityManager class is part of the com.heybanco.baas.consumer package and provides methods for generating an authorization token, sending HTTP requests, signing and encrypting payloads, and decrypting and verifying signed payloads. `Spanish translation:` La clase SecurityManager forma parte del paquete com.heybanco.baas.consumer y proporciona métodos para generar un token de autorización, enviar peticiones HTTP, firmar y cifrar payloads, y descifrar y verificar payloads firmados.


This class depends on the following external libraries. `Spanish translation:` Esta clase depende de las siguientes bibliotecas externas.

    com.nimbusds:nimbus-jose-jwt:9.30.2
    org.bouncycastle:bcpkix-jdk15on:1.50
    Java HTTP Client version 11.0.2

## Usage `Spanish translation:` Uso

Step 1: Define the SecurityManager class with the following variables and builds an SecurityManager object with the specified Properties `Spanish translation:` Paso 1: Define la clase SecurityManager con las siguientes variables y construye un objeto SecurityManager con las Propiedades especificadas

```java
package com.heybanco.baas.consumer;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import java.security.*;
import java.security.cert.CertificateException;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;

public class SecurityManager {

    private JWK jwkPublicRSA;
    private JWK jwkPrivateRSA;
    private static final String TOKEN_ENDPOINT = "/auth/v1/oidc/token";
    private static final String HOSTNAME_VALUE = "HOSTNAME";
    private static final String HTTP_METHOD = "POST";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String SSL_PROTOCOL = "TLS";
    private static final String OAUTH_GRANT_TYPE_VALUE = "client_credentials";
    private static final String OAUTH_GRANT_TYPE = "grant_type";
    private static final String OAUTH_CLIENT_ID = "client_id";
    private static final String OAUTH_CLIENT_SECRET = "client_secret";
    private static final String OAUTH_CLIENT_ID_VALUE = "OAUTH_CLIENT_ID";
    private static final String OAUTH_CLIENT_SECRET_VALUE = "OAUTH_CLIENT_SECRET";
    private static final String EQUALS_SYMBOL = "=";
    private static final String AMPERSAND = "&";
    private static final String KEYSTORE_PATH_VALUE = "KEYSTORE_PATH";
    private static final String KEYSTORE_PASSWORD_VALUE = "KEYSTORE_PASSWORD";
    private static final String PRIVATE_KEY_VALUE = "PRIVATE_KEY";
    private static final String PUBLIC_KEY_VALUE = "PUBLIC_KEY";
    private static final String HEADER_KEY = "Content-Type";
    private static final String HEADER_VALUE = "application/x-www-form-urlencoded";
    private final Properties properties;

        public SecurityManager(Properties properties) {
         this.properties = properties;
    }
}


```
Step 2: Creates getAuthorizationToken method. `Spanish translation:` Paso 2 Crea el método getAuthorizationToken.
Generates an authorization token using client credentials grant type. This method makes a POST request to a specified token URL with the client ID and client secret. `Spanish translation:` Paso 2: Genera un token de autorización utilizando el tipo de concesión de credenciales de cliente. Este método realiza una solicitud POST a una URL de token especificada con el ID de cliente y la clave secreta de cliente.
```java
   public String getAuthorizationToken()
            throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException,
            NoSuchAlgorithmException, KeyManagementException, URISyntaxException, InterruptedException {
        String requestBody = OAUTH_GRANT_TYPE + EQUALS_SYMBOL + OAUTH_GRANT_TYPE_VALUE
                + AMPERSAND + OAUTH_CLIENT_ID + EQUALS_SYMBOL + properties.getProperty(OAUTH_CLIENT_ID_VALUE)
                + AMPERSAND + OAUTH_CLIENT_SECRET + EQUALS_SYMBOL + properties.getProperty(OAUTH_CLIENT_SECRET_VALUE);
        Map<String, String> headers = new HashMap<>();
        headers.put(HEADER_KEY, HEADER_VALUE);
        HttpClient httpClient = HttpClient.newBuilder()
                .sslContext(getSSLContext())
                .build();
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(new URI(properties.getProperty(HOSTNAME_VALUE) + TOKEN_ENDPOINT))
                .method(HTTP_METHOD, HttpRequest.BodyPublishers.ofString(requestBody));
        headers.forEach(requestBuilder::header);
        HttpResponse<String> response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
```

Step 3: Creates the method to sign and encrypt the payload. `Spanish translation:` Paso 3: Crea el método para firmar y encriptar el payload.
```java
    public String signAndEncryptPayload(String requestPayload, String bApplication) throws IOException, JOSEException {
        loadKeys();
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(bApplication).build();
        Payload jwsPayload = new Payload(requestPayload);
        JWSObject jwsObject = new JWSObject(jwsHeader, jwsPayload);
        jwsObject.sign(new RSASSASigner(jwkPrivateRSA.toRSAKey()));
        JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .keyID(bApplication).build();
        JWEObject jweObject = new JWEObject(jweHeader, new Payload(jwsObject.serialize()));
        jweObject.encrypt(new RSAEncrypter(jwkPublicRSA.toRSAKey().toPublicJWK()));
        return jweObject.serialize();
    }
```
Step 4: Create the method  to decrypt and verify the signed payload. `Spanish translation:` Paso 4: Crea el método para descifrar y verificar el payload firmado.

```java
  public String decryptAndVerifySignPayload(String requestPayload) throws IOException, ParseException, JOSEException {
        loadKeys();
        JWEObject jweObject = JWEObject.parse(requestPayload);
        JWEDecrypter decrypter = new RSADecrypter(jwkPrivateRSA.toRSAKey());
        jweObject.decrypt(decrypter);
        String strDecrypt = jweObject.getPayload().toString();
        JWSObject jwsObject = JWSObject.parse(strDecrypt);
        JWSVerifier verifier = new RSASSAVerifier(jwkPublicRSA.toRSAKey().toPublicJWK());
        return jwsObject.verify(verifier) ? jwsObject.getPayload().toString() : "";
    }
```
Step 5: Creates getSSLContext method. `Spanish translation:` Paso 5: Crea el método getSSLContext. 

Obtains an SSL context with the specified key store and password. `Spanish translation:` Obtiene un contexto SSL con el almacén de claves y la contraseña especificados.
```java
    public SSLContext getSSLContext() throws KeyStoreException, IOException, CertificateException,
            NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {

        KeyStore clientKeyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        clientKeyStore.load(new FileInputStream(this.properties.getProperty(KEYSTORE_PATH_VALUE)),
                this.properties.getProperty(KEYSTORE_PASSWORD_VALUE).toCharArray());
        KeyManagerFactory keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManager.init(clientKeyStore, this.properties.getProperty(KEYSTORE_PASSWORD_VALUE).toCharArray());
        SSLContext sslContext = SSLContext.getInstance(SSL_PROTOCOL);
        sslContext.init(keyManager.getKeyManagers(), null, null);
        return sslContext;
    }
```
Step 6: Creates loadKeys method. `Spanish translation:` Paso 6: Crea el método loadKeys. 

Parses the private and public keys in PEM format and sets them as JWK objects. `Spanish translation:` Analiza las claves privada y pública en formato PEM y las establece como objetos JWK.
```java
    private void loadKeys() throws IOException, JOSEException {
        jwkPrivateRSA = JWK.parseFromPEMEncodedObjects(readFile(this.properties.getProperty(PRIVATE_KEY_VALUE)));
        jwkPublicRSA = JWK.parseFromPEMEncodedObjects(readFile(this.properties.getProperty(PUBLIC_KEY_VALUE)));
    }	

```
Step 7 Creates readFile method. `Spanish translation:` Paso 7 Crea el método readFile. 

Reads the contents of a file as a string. `Spanish translation:` Lee el contenido de un fichero como cadena.
```java
    private static String readFile(String filePath) throws IOException {
        return Files.readString(Path.of(filePath));
    }	

```
# Create the APIConsumer Class `Spanish translation:` Crea la clase APIConsumer

The APIConsumer class is part of the com.heybanco.baas.consumer package. It is an example implementation of an API client that uses the SecurityManager class described in the previous steps. `Spanish translation:` La clase APIConsumer forma parte del paquete com.heybanco.baas.consumer. Es un ejemplo de implementación de un cliente API que utiliza la clase SecurityManager descrita en los pasos anteriores.


Step 1: Define the ApiConsumer class with the following variables. `Spanish translation:` Paso 1: Define la clase ApiConsumer con las siguientes variables.

```java

package com.heybanco.baas.consumer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;

public class ApiConsumer {
    private static final Logger logger = Logger.getLogger(ApiConsumer.class.getName());
    private static final String HOSTNAME_VALUE = "HOSTNAME";
    private static final String B_APPLICATION_VALUE = "B_APPLICATION";
    private static final String BASE_PATH = "/taas/v1.0";
    private static final String ENDPOINT = "/accounts";
    String method = "POST";
}

```
Step 2: Define the main() method within the ApiConsumer class, create a Properties object to store the configuration properties and create a new instance of the SecurityManager class. `Spanish translation:` Paso 2: Define el método main() dentro de la clase ApiConsumer, crea un objeto Properties para almacenar las propiedades de configuración y crea una nueva instancia de la clase SecurityManager.

```java
public static void main(String[] args) {
   Properties properties = new Properties();
   SecurityManager securityManager = new SecurityManager(properties);
}

```
Step 3: Load the configuration properties from the config.properties file. `Spanish translation:` Paso3: Cargar las propiedades de configuración desde el archivo config.properties.

```java

try {
      FileInputStream input = new FileInputStream("../APIConsumer/src/main/resources/config.properties");
      properties.load(input);
      input.close();
} catch (IOException e) {
      logger.log(Level.WARNING, "Error loading configuration properties: " + e.getMessage());
}
```
Step 4: Generate an authorization token. `Spanish translation:` Paso 4: Generar un token de autorización.
```java
 JsonObject jsonResponse = JsonParser.parseString(securityManager.getAuthorizationToken())
                                        .getAsJsonObject();
String accessToken = jsonResponse.get("access_token").getAsString();

```
 Step 5: Define headers and request body. ` Spanish translation:` Paso 5: Definir las cabeceras y el cuerpo de la solicitud.

 ```java
 Map<String, String> headers = new HashMap<String, String>() {
};
headers.put("Accept", "application/json");
headers.put("Content-Type", "application/json");
headers.put("B-Transaction", "123456789");
headers.put("Accept-Charset", "UTF-8");
headers.put("B-application", properties.getProperty(B_APPLICATION_VALUE));
headers.put("Authorization", "Bearer " + accessToken);
String requestPayload = "{\"taxRegimeId\": 2,\"name\": \"Jose Luis\",\"lastName\": \"Lemus\",\"secondLastName\": \"Valdivia\",\"businessName\": \"\",\"birthday\": \"1996-10-03\",\"rfc\": \"LEVL961003KQ0\",\"curp\": \"LEVL961003HBSMLS06\",\"callingCode\": \"52\",\"cellPhoneNumber\": \"3311065681\",\"email\": \"jose.lemus@banregio.com\",\"nationalityId\": \"001\",\"countryId\": \"01\",\"stateId\": \"047\",\"cityId\": \"04701005\",\"legalRepresentative\": {\"name\": \"\",\"lastName\": \"\",\"secondLastName\": \"\"}}";
```

Step 6: Sign and encrypt the request body and convert the signed and encrypted payload to JSON. ` Spanish translation:` Paso 6: Firmar y cifrar el cuerpo de la solicitud y convertir el payload firmado y cifrado a JSON.

 ```java
  String encryptedPayload = securityManager.signAndEncryptPayload(requestPayload,
                                        properties.getProperty(B_APPLICATION_VALUE));
  String signedEncryptedPayloadJson = "{\"data\":\"" + encryptedPayload + "\"}";

```

 Step 7: Make the API request with the signed and encrypted payload. And Print the response. ` Spanish translation:` Paso 7: Realizar la petición API con el payload firmado y encriptado. E Imprime la respuesta.

 ```java
HttpClient httpClient = HttpClient.newBuilder()
                                        .sslContext(securityManager.getSSLContext())
                                        .build();
HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create((properties.getProperty(HOSTNAME_VALUE) + BASE_PATH
                    + ENDPOINT)))
                    .method(method, HttpRequest.BodyPublishers.ofString(requestPayload));
headers.forEach(requestBuilder::header);
HttpResponse<String> response = httpClient.send(requestBuilder.build(),
HttpResponse.BodyHandlers.ofString());
String responseHeaders = response.headers().map().toString();
String responseBody = response.body();
logger.log(Level.INFO, "Response headers: " + responseHeaders);
logger.log(Level.INFO, "Response body: " + responseBody);
Optional<String> locationHeader = response.headers().firstValue("location");

```

 Step 8: Validates if the request was successful and makes another request to the API to query the Id information obtained in the previous request. ` Spanish translation:` Paso 8: Valida si la petición se ha realizado correctamente y realiza otra petición a la API para consultar la información de Id obtenida en la petición anterior.

 ```java
if (locationHeader.isPresent()) {
    requestBuilder = HttpRequest.newBuilder()
    .uri(URI.create((properties.getProperty(HOSTNAME_VALUE) + BASE_PATH
    + locationHeader.get())))
    .GET();
    headers.remove("Content-Type");
    headers.forEach(requestBuilder::header);
    HttpResponse<String> responseEncript = httpClient.send(requestBuilder.build(),
                         HttpResponse.BodyHandlers.ofString());
    String responseBodyEncrypt = responseEncript.body();
    logger.log(Level.INFO, "Response body encrypted: " + responseBodyEncrypt);
    jsonResponse = JsonParser.parseString(responseBodyEncrypt).getAsJsonObject();

}

```
Step 9: If the encrypted response body is not empty, decrypt and verify the signed payload. ` Spanish translation:` Paso 9: Si el cuerpo de la respuesta cifrada no está vacío, descifre y verifique el payload firmado.

 ```java
                        
jsonResponse = JsonParser.parseString(responseBodyEncrypt).getAsJsonObject();
String decryptedPayload = securityManager
            .decryptAndVerifySignPayload(jsonResponse.get("data").getAsString());
logger.log(Level.INFO, "Decrypted response body: " + decryptedPayload);

```