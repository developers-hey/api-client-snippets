using System;
using Newtonsoft.Json.Linq;

namespace ApiClient
{
    class ApiClientImp
    {
        static async Task Main(string[] args)
        {
            var endpoint = "/accounts";
            var basePath = "/taas/v1.0";
            var hostname = " https://test-api-tech.hey.inc";
            var clientId = "159c9a7f-ca3f-4a26-b70b-03c0e652118c";
            var clientSecret = "0b3da38f-6116-415a-bad5-39882986e6e0";
            var requestBody =
                "{\"taxRegimeId\": 2,\"name\": \"Jose Luis\",\"lastName\": \"Lemuss\",\"secondLastName\": \"Valdivia\",\"businessName\": \"\",\"birthday\": \"1996-10-03\",\"rfc\": \"LEVL961003KQ0\",\"curp\": \"LEVL961003HBSMLS06\",\"callingCode\": \"52\",\"cellPhoneNumber\": \"3311065681\",\"email\": \"jose.lemus@banregio.com\",\"nationalityId\": \"001\",\"countryId\": \"01\",\"stateId\": \"047\",\"cityId\": \"04701005\",\"legalRepresentative\": {\"name\": \"\",\"lastName\": \"\",\"secondLastName\": \"\"}}";
            var apiClient = new SecurityManager(hostname, clientId, clientSecret);
            var token = await apiClient.GetAccessTokenAsync();
            var signedEncryptedPayload = apiClient.SignAndEncryptPayload(requestBody);
            var signedEncryptedPayloadJson = "{\"data\":\"" + signedEncryptedPayload + "\"}";
            var response = await apiClient.MakeApiRequestAsync(
                basePath + endpoint,
                token,
                "POST",
                signedEncryptedPayloadJson
            );
            Console.WriteLine(response.Headers);
            var responseBody = await response.Content.ReadAsStringAsync();
            Console.WriteLine(responseBody);
            var responseEncript = await apiClient.MakeApiRequestAsync(
                basePath + response.Headers.Location,
                token,
                "GET",
                null
            );
            Console.WriteLine(responseEncript.Headers);
            string responseEncriptBody = await responseEncript.Content.ReadAsStringAsync();
            Console.WriteLine(responseEncriptBody);
            if (!String.IsNullOrEmpty(responseEncriptBody))
            {
                String responseData = JObject.Parse(responseEncriptBody).Value<string>("data");
                var decryptedPayload = apiClient.decryptAndVerifySignPayload(responseData);
                Console.WriteLine(decryptedPayload);
            }
        }
    }
}
