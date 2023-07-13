# Description `Spanish translation:` Descripción

This Documentation provides classes to help consume Banking as a Service (BaaS) APIs in a secure manner. These classes implement security best practices to ensure that user data is protected. `Spanish translation:` Esta documentación proporciona clases para ayudar a consumir las API de Banking as a Service (BaaS) de forma segura. Estas clases implementan las mejores prácticas de seguridad para garantizar la protección de los datos de los usuarios.

### Prerequisites `Spanish translation:`  Requisitos previos 

The authentication credentials required to access the BaaS API must have been created. `Spanish translation:`  Se deben haber creado las credenciales de autenticación necesarias para acceder a la API de BaaS. 

# SecurityManager  Class 

This is a C# class that provides functionality for making secure API requests to a server, including authentication and encryption of payloads. `Spanish translation:` Esta es una clase C# que proporciona funcionalidad para realizar peticiones API seguras a un servidor, incluyendo autenticación y encriptación de cargas útiles. 

The class makes use of the following libraries.  `Spanish translation:` La clase hace uso de las siguientes bibliotecas: 

```C#
dotnet new console --framework net7.0
dotnet add package jose-jwt --version 4.1.0
dotnet add package Newtonsoft.Json.Linq;
```
# Usage

## Step 1: Create namespace and declare attributes. `Spanish translation:`  Crear el namespace y declarar atributos.

 Create the ApiClient namespace where the SecurityManager class is defined. Then, declare the following attributes. `Spanish translation:` Crea el namespace ApiClient donde se define la clase SecurityManager. A continuación, declare los siguientes atributos.

1.  **httpClient**: An instance of HttpClient used to make HTTP requests. `Spanish translation:`  Una instancia de HttpClient utilizada para realizar peticiones HTTP.
2. **_hostname**: A string representing the base URL for the Hey Inc API. `Spanish translation:` Una cadena que representa la URL base de la API.
**_clientId**: A string representing the client ID used for authentication. `Spanish translation:`  Una cadena que representa el ID de cliente utilizado para la autenticación.
3. **_clientSecret**: A string representing the client secret used for authentication. `Spanish translation:` cadena que representa el secreto de cliente utilizado para la autenticación.
4. **certificatePath**: A string representing the path to the client certificate file. `Spanish translation:` Una cadena que representa la ruta al archivo de certificado del cliente.
5. **certificatePassword**: A string representing the password for the client certificate file. `Spanish translation:` Cadena que representa la contraseña del archivo de certificado del cliente.
6. **publicKeyPath**: A string representing the path to the server public key file. `Spanish translation:` Una cadena que representa la ruta al archivo de clave pública del servidor.
7. **b_Application**: A string representing the application ID. `Spanish translation:` Una cadena que representa el ID de la aplicación. 
token_Endpoind: A string representing the endpoint for obtaining an access token. `Spanish translation:` Una cadena que representa el punto final para obtener un token de acceso.
8. **certificate**: An instance of X509Certificate2 representing the client certificate. `Spanish translation:`  Una instancia de X509Certificate2 que representa el certificado del cliente.
```C#
        private HttpClient _httpClient;
        private readonly string _hostname = "https://test-api-tech.hey.inc";
        private readonly string _clientId;
        private readonly string _clientSecret;
        private string certificatePath =
            "./resources/Client_KeyStore_test_8971c75a-690f-430d-bbac-ca944d3b6de9.p12";
        private string certificatePassword = "NGABinKkqj3gHsBQXuK3YaZtjQ33ogARUXfo5ugMuTk=";
        private readonly string publicKeyPath =
            "./resources/Server_Public_test_8971c75a-690f-430d-bbac-ca944d3b6de9.pem";
        private readonly string b_Application = "8971c75a-690f-430d-bbac-ca944d3b6de9";
        private readonly string token_Endpoind = "/auth/v1/oidc/token";
        private readonly X509Certificate2 certificate;
```
### 1.1 Create constructs a SecurityManager object with the specified parameters. `Spanish translation:` Crea un constructor SecurityManager con los parámetros

```C#
public SecurityManager(string hostname, string clientId, string clientSecret)
        {
            _hostname = hostname;
            _clientId = clientId;
            _clientSecret = clientSecret;
            certificate = new X509Certificate2(certificatePath, certificatePassword);
        }
```
The hostname, clientId, and clientSecret parameters are required when creating a new SecurityManager instance. The hostname parameter should be set to the base URL of the API you are connecting to, while the clientId and clientSecret parameters should be the credentials provided by the API.  `Spanish translation:` Los parámetros hostname, clientId y clientSecret son necesarios al crear una nueva instancia de SecurityManager. El parámetro hostname debe ajustarse a la URL base de la API a la que se está conectando, mientras que los parámetros clientId y clientSecret deben ser las credenciales proporcionadas por la API.

## Step 2 Generate an access token 
Generates an authorization token using client credentials grant type. This method makes a POST request to a specified token URL with the client ID and client secret. `Spanish translation:` Genera un token de autorización utilizando el tipo de concesión de credenciales de cliente. Este método realiza una solicitud POST a una URL de token especificada con el ID de cliente y el secreto de cliente.


```C#
public async Task<string> GetAccessTokenAsync()
        {
            var tokenUrl = _hostname + token_Endpoind;

            var requestContent = new FormUrlEncodedContent(
                new[]
                {
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new KeyValuePair<string, string>("client_id", _clientId),
                    new KeyValuePair<string, string>("client_secret", _clientSecret),
                }
            );
            var handler = new HttpClientHandler();
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ServerCertificateCustomValidationCallback = ValidateCertificate;
            handler.ClientCertificates.Add(certificate);
            _httpClient = new HttpClient(handler);
            var response = await _httpClient.PostAsync(tokenUrl, requestContent);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception(
                    $"Failed to get access token. Response status code: {response.StatusCode}, response body: {responseBody}"
                );
            }

            var token = JObject.Parse(responseBody).Value<string>("access_token");
            return token;
        }
```
## Step 3  Making an API request `Spanish translation:` Realizar una solicitud API

Make an API request by calling the MakeApiRequestAsync method. Spanish translation:` Spanish translation:` Realice una solicitud de API llamando a MakeApiRequestAsync.

The endpoint parameter should be the path of the API endpoint you want to access, while the method parameter should be the HTTP method you want to use (e.g. "GET", "POST", "PUT", etc.). The requestBody parameter is optional and should be used when making a request with a request body. `Spanish translation:` El parámetro endpoint debe ser la ruta del punto final de la API al que desea acceder, mientras que el parámetro method debe ser el método HTTP que desea utilizar (por ejemplo, "GET", "POST", "PUT", etc.). El parámetro requestBody es opcional y debe utilizarse cuando se realiza una solicitud con un cuerpo de solicitud.
```C#
public async Task<HttpResponseMessage> MakeApiRequestAsync(
            string endpoint,
            string token,
            string method,
            string requestBody
        )
        {
            var apiUrl = $"{_hostname}{endpoint}";
            var handler = new HttpClientHandler();
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ServerCertificateCustomValidationCallback = ValidateCertificate;
            handler.ClientCertificates.Add(certificate);
            _httpClient = new HttpClient(handler);
            var request = new HttpRequestMessage(new HttpMethod(method), apiUrl);
            if (!String.IsNullOrEmpty(requestBody))
            {
                request.Content = new StringContent(requestBody, Encoding.UTF8, "application/json");
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            }
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.AcceptCharset.Add(new StringWithQualityHeaderValue("UTF-8"));
            request.Headers.Add("B-Transaction", "111111111111");
            request.Headers.Add("B-application", b_Application);
            var response = await _httpClient.SendAsync(request);
            var responseContent = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode)
            {
                throw new Exception(
                    $"Failed to make API request. Response status code: {response.StatusCode}, response body: {responseContent}"
                );
            }

            return response;
        }
```
## Step 4 Signs and encrypts the payload. ` Spanish translation:` Firma y encripta la carga útil.

To sign and encrypt a payload, use the SignAndEncryptPayload() method. ` Spanish translation:` Para firmar y cifrar una carga útil, utilice el método SignAndEncryptPayload().

```C#
public string SignAndEncryptPayload(string requestPayload)
        {
            var rsaPrivate = new X509Certificate2(
                certificatePath,
                certificatePassword
            ).GetRSAPrivateKey();
            var publicKey = File.ReadAllText(publicKeyPath, Encoding.UTF8);
            RSA rsaPublic = LoadRsaKey(publicKey);
            var headers = new Dictionary<string, object>() { { "kid", b_Application } };
            string signedPayload = Jose.JWT.Encode(requestPayload, rsaPrivate, JwsAlgorithm.RS256);
            string signedEncryptedPayload = Jose.JWT.Encode(
                signedPayload,
                rsaPublic,
                JweAlgorithm.RSA_OAEP_256,
                JweEncryption.A256GCM,
                extraHeaders: headers
            );
            return signedEncryptedPayload;
        }
```

The payload parameter should be a JSON string representing the payload you want to encrypt. The method returns an encrypted payload string. ` Spanish translation:` El parámetro de carga útil debe ser una cadena JSON que represente la carga útil que desea cifrar. El método devuelve una cadena de carga cifrada.

## Step 5 Decrypts and verifies the signature of a JWE/JWS payload. ` Spanish translation:`  Descifra y verifica la firma de una carga útil JWE/JWS.
To decrypt and verify a signed payload, use the decryptAndVerifySignPayload() method. ` Spanish translation:`  Para descifrar y verificar una carga firmada, utiliza el método decryptAndVerifySignPayload().
```C#
public string decryptAndVerifySignPayload(string encryptedPayload)
        {
            var rsaPrivate = new X509Certificate2(
                certificatePath,
                certificatePassword
            ).GetRSAPrivateKey();
            var payloadValidate = Jose.JWT.Decode(encryptedPayload, rsaPrivate);
            var decryptedPayload = Jose.JWT.Payload(payloadValidate);
            return decryptedPayload;
        }
```
The encryptedPayload parameter should be an encrypted payload string. The method returns a JSON string representing the decrypted payload. ` Spanish translation:` El parámetro encryptedPayload debe ser una cadena de carga cifrada. El método devuelve una cadena JSON que representa la carga útil descifrada.

## Step 6 Declare the following private methods. ` Spanish translation:`  Declara los siguientes métodos privados.


Loads an RSA key from a given PEM encoded string. ` Spanish translation:` Carga una clave RSA a partir de una cadena codificada en PEM.
```C#
private RSA LoadRsaKey(string pemKey)
        {
            RSA rsa = RSA.Create();
            rsa.ImportFromPem(pemKey);
            return rsa;
        }
```      


Validates the SSL certificate associated with an HTTP request message. ` Spanish translation:` Valida el certificado SSL asociado a un mensaje de solicitud HTTP.
```C#
        private static bool ValidateCertificate(
            HttpRequestMessage requestMessage,
            X509Certificate2 certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors
        )
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true;
            }

            return false;
        }

``` 
## Example implementation of an API client  ` Spanish translation:` Ejemplo de implementación de un cliente API.

 Example implementation of an API client using the SecurityManager class described in the previous steps. ` Spanish translation:` Ejemplo de implementación de un cliente API utilizando la clase SecurityManager descrita en los pasos anteriores.

 Step 1: Define the API endpoint, base path, hostname, client ID, client secret, and request body. ` Spanish translation:` Paso 1: Definir el punto final de la API, la ruta base, el nombre de host, el ID de cliente, el secreto de cliente y el cuerpo de la solicitud.
 ```C#
            var endpoint = "/accounts";
            var basePath = "/taas/v1.0";
            var hostname = " https://test-api-tech.hey.inc";
            var clientId = "159c9a7f-ca3f-4a26-b70b-03c0e652118c";
            var clientSecret = "0b3da38f-6116-415a-bad5-39882986e6e0";
            var requestBody = "{\"taxRegimeId\": 2,\"name\": \"Jose Luis\",\"lastName\": \"Lemuss\",\"secondLastName\": \"Valdivia\",\"businessName\": \"\",\"birthday\": \"1996-10-03\",\"rfc\": \"LEVL961003KQ0\",\"curp\": \"LEVL961003HBSMLS06\",\"callingCode\": \"52\",\"cellPhoneNumber\": \"3311065681\",\"email\": \"jose.lemus@banregio.com\",\"nationalityId\": \"001\",\"countryId\": \"01\",\"stateId\": \"047\",\"cityId\": \"04701005\",\"legalRepresentative\": {\"name\": \"\",\"lastName\": \"\",\"secondLastName\": \"\"}}";
``` 
Step 2: Create a new instance of the SecurityManager class with the hostname, client ID, and client secret. ` Spanish translation:` Paso 2: Crear una nueva instancia de la clase SecurityManager con el nombre de host, el ID de cliente y el secreto de cliente.
 ```C#
var apiClient = new SecurityManager(hostname, clientId, clientSecret);
```   
Step 3: Get an access token from the API. ` Spanish translation:` Paso 3: Obtener un token de acceso de la API.
 ```C#
var token = await apiClient.GetAccessTokenAsync();
```   
Step 4: Sign and encrypt the request body. ` Spanish translation:` Paso 4: Firmar y cifrar el cuerpo de la solicitud.

 ```C#
var signedEncryptedPayload = apiClient.SignAndEncryptPayload(requestBody);
 ``` 
 Step 5: Convert the signed and encrypted payload to JSON. ` Spanish translation:` Paso 5: Convertir la carga útil firmada y cifrada en JSON.

 ```C#
var signedEncryptedPayloadJson = "{\"data\":\"" + signedEncryptedPayload + "\"}";
 ``` 
 Step 6: Make the API request with the signed and encrypted payload. And Print the response. ` Spanish translation:` Paso 6: Realizar la petición API con la carga útil firmada y encriptada. E Imprime la respuesta.
 ```C#
 var response = await apiClient.MakeApiRequestAsync(basePath + endpoint, token, "POST", signedEncryptedPayloadJson);
 Console.WriteLine(response.Headers);
 var responseBody = await response.Content.ReadAsStringAsync();
 Console.WriteLine(responseBody);
 ``` 
 Step 7: Make another API request to get the encrypted response. ` Spanish translation:` Paso 7: Realice otra solicitud API para obtener la respuesta cifrada.
 ```C#
 var responseEncript = await apiClient.MakeApiRequestAsync(basePath + response.Headers.Location, token, "GET", null);
  Console.WriteLine(responseEncript.Headers);
  string responseEncriptBody = await responseEncript.Content.ReadAsStringAsync();
  Console.WriteLine(responseEncriptBody);
 ``` 
Step 8: If the encrypted response body is not empty, decrypt and verify the signed payload. ` Spanish translation:` Paso 8: Si el cuerpo de la respuesta cifrada no está vacío, descifre y verifique el archivo firmado.
 ```C#
   if (!String.IsNullOrEmpty(responseEncriptBody))
            {
                String responseData = JObject.Parse(responseEncriptBody).Value<string>("data");
                var desencriptPayload = apiClient.decryptAndVerifySignPayload(responseData);
                Console.WriteLine(desencriptPayload);
            }
 ``` 




