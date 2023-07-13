/**
* Provides security-related functionality for making API requests
*/
namespace ApiClient
{
    using System;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Text;
    using System.Threading.Tasks;
    using Newtonsoft.Json.Linq;
    using System.Security.Cryptography.X509Certificates;
    using System.Net.Security;
    using Jose;
    using System.Security.Cryptography;
    using System.IO;
    using Org.BouncyCastle.Crypto.Parameters;
    using System.Collections.Generic;

    public class SecurityManager
    {
        private HttpClient _httpClient;
        private readonly string _hostname = "https://sbox-api-tech.hey.inc";
        private readonly string _clientId;
        private readonly string _clientSecret;
        private string certificatePath =
            "./resources/Client_KeyStore_sbox.p12";
        private string certificatePassword = "e9YJNQvhavZRtM4vIxVsaAP8oQOO9Sv4k+LX+nQqBC0=";
        private readonly string publicKeyPath =
            "./resources/Server_Public_sbox.pem";
        private readonly string b_Application = "8971c75a-690f-430d-bbac-ca944d3b6de9";
        private readonly string token_Endpoind = "/auth/v1/oidc/token";
        private readonly X509Certificate2 certificate;

        /**
  * Constructs a SecurityManager object with the specified parameters.
  *
  * @param certificatePath The file path of the X509 certificate used for signing and encrypting payloads.
  * @param certificatePassword The password for the X509 certificate.
  * @param publicKeyPath The file path of the public key used for encrypting payloads.
  * @param b_Application The B-Application header value used for API requests.
  * @param hostname The hostname of the API endpoint.
  */
        public SecurityManager(string hostname, string clientId, string clientSecret)
        {
            _hostname = hostname;
            _clientId = clientId;
            _clientSecret = clientSecret;
            certificate = new X509Certificate2(certificatePath, certificatePassword);
        }

        /**
       * Generates an authorization token using client credentials grant type.
       * This method makes a POST request to a specified token URL with the client ID and client secret.
       * @return A Task that represents the asynchronous operation.
       * The task result contains the access token string
       */
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

        /**
          * Sends an API request to the specified endpoint with the specified token, method, and request body.
          *
          * @param endpoint The API endpoint to send the request to.
          * @param token The access token to include in the Authorization header.
          * @param method The HTTP method to use for the request.
          * @param requestBody The JSON string to include in the request body.
          *
          * @return The HttpResponseMessage object returned by the API.
          *
          * @throws Exception if the API request is unsuccessful.
          */
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

        /**
             * Signs and encrypts the payload using RSA 256 algorithm.
             *
             * @param requestPayload the payload to be signed and encrypted
             * @return the signed and encrypted payload as a string
             */
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

        /**
         * decrypts and verifies the signature of a JWE/JWS payload.
         *
         * @param encryptedPayload the JWE/JWS payload to be decrypted and verified
         * @return the decrypted and verified payload
         */
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

        /**
          Loads an RSA key from a PEM string.
          @param pemKey the PEM string containing the RSA key.
          @return an RSA object containing the loaded key.
        */
        private RSA LoadRsaKey(string pemKey)
        {
            RSA rsa = RSA.Create();
            rsa.ImportFromPem(pemKey);
            return rsa;
        }

        /**
            Validates the SSL certificate associated with an HTTP request message.
            @param requestMessage The HTTP request message containing the certificate.
            @param certificate The X509 certificate to be validated.
            @param chain The X509 certificate chain.
            @param sslPolicyErrors The SSL policy errors to check for validation.
            @return True if the certificate is valid according to the specified SSL policy errors; otherwise, false.
            */
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
    }
}
