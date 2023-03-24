# SecurityManager C# Class

This is a C# class that provides functionality for making secure API requests to a server, including authentication and encryption of payloads. The class makes use of the following libraries:

## Installation

```C#
dotnet add package jose-jwt --version 4.1.0
dotnet add package Newtonsoft.Json.Linq;
```
## Description 

Import the ApiClient namespace where the SecurityManager class is defined.

 Declare the following attributes: 

    _httpClient: An instance of HttpClient used to make HTTP requests.
    _hostname: A string representing the base URL for the Hey Inc API.
    _clientId: A string representing the client ID used for authentication.
    _clientSecret: A string representing the client secret used for authentication.
    certificatePath: A string representing the path to the client certificate file.
    certificatePassword: A string representing the password for the client certificate file.
    publicKeyPath: A string representing the path to the server public key file.
    b_Application: A string representing the application ID.
    token_Endpoind: A string representing the endpoint for obtaining an access token.
    certificate: An instance of X509Certificate2 representing the client certificate.
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
Create constructs a SecurityManager object with the specified parameters.

```C#
public SecurityManager(string hostname, string clientId, string clientSecret)
        {
            _hostname = hostname;
            _clientId = clientId;
            _clientSecret = clientSecret;
            certificate = new X509Certificate2(certificatePath, certificatePassword);
        }
```
The hostname, clientId, and clientSecret parameters are required when creating a new SecurityManager instance. The hostname parameter should be set to the base URL of the API you are connecting to, while the clientId and clientSecret parameters should be the credentials provided by the API.

## Generating an access token
Generates an authorization token using client credentials grant type. This method makes a POST request to a specified token URL with the client ID and client secret.


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
## Making an API request

Make an API request by calling the MakeApiRequestAsync method, 

The endpoint parameter should be the path of the API endpoint you want to access, while the method parameter should be the HTTP method you want to use (e.g. "GET", "POST", "PUT", etc.). The requestBody parameter is optional and should be used when making a request with a request body.

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

## Signs and encrypts the payload 

To sign and encrypt a payload, use the SignAndEncryptPayload() method:
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

The payload parameter should be a JSON string representing the payload you want to encrypt. The method returns an encrypted payload string.

## Decrypts and verifies the signature of a JWE/JWS payload.
To decrypt and verify a signed payload, use the decryptAndVerifySignPayload() method:
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
The encryptedPayload parameter should be an encrypted payload string. The method returns a JSON string representing the decrypted payload.

## Loads an RSA key from a PEM.
Loads an RSA key from a given PEM encoded string.
```C#
private RSA LoadRsaKey(string pemKey)
        {
            RSA rsa = RSA.Create();
            rsa.ImportFromPem(pemKey);
            return rsa;
        }
```      

## Validates the SSL certificate
Validates the SSL certificate associated with an HTTP request message. 
```C#
        public static bool ValidateCertificate(
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
## Example of implementation 

```C#
    class ApiClientImp
    {
        static async Task Main(string[] args)
        {
            Define the API endpoint, base path, hostname, client ID, client secret, and request body.

            var endpoint = "/accounts";
            var basePath = "/taas/v1.0";
            var hostname = " https://test-api-tech.hey.inc";
            var clientId = "159c9a7f-ca3f-4a26-b70b-03c0e652118c";
            var clientSecret = "0b3da38f-6116-415a-bad5-39882986e6e0";
            var requestBody = "{\"taxRegimeId\": 2,\"name\": \"Jose Luis\",\"lastName\": \"Lemuss\",\"secondLastName\": \"Valdivia\",\"businessName\": \"\",\"birthday\": \"1996-10-03\",\"rfc\": \"LEVL961003KQ0\",\"curp\": \"LEVL961003HBSMLS06\",\"callingCode\": \"52\",\"cellPhoneNumber\": \"3311065681\",\"email\": \"jose.lemus@banregio.com\",\"nationalityId\": \"001\",\"countryId\": \"01\",\"stateId\": \"047\",\"cityId\": \"04701005\",\"legalRepresentative\": {\"name\": \"\",\"lastName\": \"\",\"secondLastName\": \"\"}}";

            Create a new instance of the SecurityManager class with the hostname, client ID, and client secret.
            var apiClient = new SecurityManager(hostname, clientId, clientSecret);

            Get an access token from the API.
            var token = await apiClient.GetAccessTokenAsync();

            Sign and encrypt the request body.
            var signedEncryptedPayload = apiClient.SignAndEncryptPayload(requestBody);
            
            Convert the signed and encrypted payload to JSON.
            var signedEncryptedPayloadJson = "{\"data\":\"" + signedEncryptedPayload + "\"}";

            Make the API request with the signed and encrypted payload.
            var response = await apiClient.MakeApiRequestAsync(basePath + endpoint, token, "POST", signedEncryptedPayloadJson);

            Print the response headers.
            Console.WriteLine(response.Headers);

            Read the response body as a string.
            var responseBody = await response.Content.ReadAsStringAsync();

            Print the response body.
            Console.WriteLine(responseBody);

            Make another API request to get the encrypted response.
            var responseEncript = await apiClient.MakeApiRequestAsync(basePath + response.Headers.Location, token, "GET", null);

            Print the response headers.
            Console.WriteLine(responseEncript.Headers);

            Read the encrypted response body as a string.
            string responseEncriptBody = await responseEncript.Content.ReadAsStringAsync();

            Print the encrypted response body.
            Console.WriteLine(responseEncriptBody);

            If the encrypted response body is not empty, decrypt and verify the signed payload.
            if (!String.IsNullOrEmpty(responseEncriptBody))
            {
                String responseData = JObject.Parse(responseEncriptBody).Value<string>("data");
                var desencriptPayload = apiClient.decryptAndVerifySignPayload(responseData);
                Console.WriteLine(desencriptPayload);
            }
        }
    }

``` 




