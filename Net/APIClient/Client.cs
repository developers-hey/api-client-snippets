using System;
using Newtonsoft.Json.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Net.Security;
using System.Text;
using System.Net.Http.Headers;
using Newtonsoft.Json;

namespace ApiClient
{
    class Client
    {
        private HttpClient httpClient;
        private static X509Certificate2 certificate;
        private static IConfigurationRoot configuration;
        private static SecurityManager securityManager;
        static async Task Main(string[] args)
        {

            configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("resources/appsettings.json")
                .Build();

            var client = new Client();
            certificate = new X509Certificate2(configuration["MTLS:KEYSTORE_PATH"], configuration["MTLS:KEYSTORE_PASSWD"]);
            securityManager = new SecurityManager(configuration);
            var accessToken = await client.GetAccessTokenAsync();
            var signedEncryptedPayload = securityManager.SignAndEncryptPayload(configuration["REQUEST:UNENCRYPTED_PAYLOAD"]);
            var signedEncryptedPayloadJson = "{\"data\":\"" + signedEncryptedPayload + "\"}";
            var response = await client.MakeRequestAsync(
                configuration["API:HOSTNAME_DNS"] + configuration["API:BASE_PATH"] + configuration["API:RESOURCE_NAME"],
                accessToken,
                configuration["REQUEST:HTTP_VERB"],
                signedEncryptedPayloadJson
            );

        }
        /**
          * Sends an API request to the specified endpoint with the specified token, method, and request body.
          *
          * @param endpoint The API endpoint to send the request to.
          * @param accessToken The access token to include in the Authorization header.
          * @param method The HTTP method to use for the request.
          * @param requestBody The JSON string to include in the request body.
          *
          * @return The HttpResponseMessage object returned by the API.
          *
          * @throws Exception if the API request is unsuccessful.
          */
        public async Task<HttpResponseMessage> MakeRequestAsync(
            string endpoint,
            string accessToken,
            string method,
            string requestBody
        )
        {
            var handler = new HttpClientHandler();
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ServerCertificateCustomValidationCallback = ValidateCertificate;
            handler.ClientCertificates.Add(certificate);
            httpClient = new HttpClient(handler);
            var request = new HttpRequestMessage(new HttpMethod(method), endpoint);
            if (!String.IsNullOrEmpty(requestBody))
            {
                request.Content = new StringContent(requestBody, Encoding.UTF8, configuration["REQUEST:MIME_TYPE"]);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue(configuration["REQUEST:MIME_TYPE"]);
            }
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(configuration["REQUEST:MIME_TYPE"]));
            request.Headers.AcceptCharset.Add(new StringWithQualityHeaderValue(configuration["REQUEST:ENCODE_CHARSET"]));
            request.Headers.Add("B-Transaction", configuration["REQUEST:B_TRANSACTION"]);
            request.Headers.Add("B-application", configuration["SUBSCRIPTION:B_APPLICATION"]);
            var response = await httpClient.SendAsync(request);
            var responseContent = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode)
            {
                throw new Exception(
                    $"Failed to make API request. Response status code: {response.StatusCode}, response body: {responseContent}"
                );
            }

            // Print relevant headers, for example: Locations contains the resource ID that have been created with POST
            if (response.Headers.TryGetValues("B-Trace", out var bTraceValues))
            {
                var bTraceValue = bTraceValues.First();
                Console.WriteLine($"B-Trace: {bTraceValue}");
            }

            if (response.Headers.Location != null)
            {
                Console.WriteLine($"Location: {response.Headers.Location}");
            }

            Console.WriteLine("Response StatusCode : " + response.StatusCode);

            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {

                var responseData = JsonConvert.DeserializeObject<Dictionary<string, object>>(responseContent);
                Dictionary<string, object> payload = new Dictionary<string, object>();
                payload["code"] = responseData["code"];
                payload["message"] = responseData["message"];
                payload["data"] = securityManager.decryptAndVerifySignPayload((string)responseData["data"]);
                Console.WriteLine("Response Body: " + JsonConvert.SerializeObject(payload));

            }
            else
            {
                Console.WriteLine("Response Body: " + responseContent);
            }

            return response;
        }

        /**
* Generates an authorization token using client credentials grant type.
* This method makes a POST request to a specified token URL with the client ID and client secret.
* @return A Task that represents the asynchronous operation.
* The task result contains the access token string
*/
        public async Task<string> GetAccessTokenAsync()
        {

            var tokenUrl = configuration["TOKEN:HOSTNAME_DNS"] + configuration["TOKEN:RESOURCE_NAME"];

            var requestContent = new FormUrlEncodedContent(
                new[]
                {
                    new KeyValuePair<string, string>("grant_type",  configuration["TOKEN:GRANT_TYPE"] ),
                    new KeyValuePair<string, string>("client_id", configuration["SUBSCRIPTION:CLIENT_ID"]),
                    new KeyValuePair<string, string>("client_secret", configuration["SUBSCRIPTION:CLIENT_SECRET"]),
                }
            );
            var handler = new HttpClientHandler();
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ServerCertificateCustomValidationCallback = ValidateCertificate;
            handler.ClientCertificates.Add(certificate);
            httpClient = new HttpClient(handler);
            var response = await httpClient.PostAsync(tokenUrl, requestContent);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception(
                    $"Failed to get access token. Response status code: {response.StatusCode}, response body: {responseBody}"
                );
            }

            return JObject.Parse(responseBody).Value<string>("access_token");
        }

        /**
            Validates the SSL certificate associated with an HTTP request message.
            @param requestMessage The HTTP request message containing the certificate.
            @param certificate The X509 certificate to be validated.
            @param chain The X509 certificate chain.
            @param sslPolicyErrors The SSL policy errors to check for validation.
            @return True if the certificate is valid according to the specified SSL policy errors; otherwise, false.
            */
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

    }


}

