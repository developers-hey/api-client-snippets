using System;
using Newtonsoft.Json.Linq;

namespace ApiClient
{
    class Client
    {
        static async Task Main(string[] args)
        {
            var endpoint = "/accounts";
            var basePath = "/taas/v1.0";
            var hostname = " https://sbox-api-tech.hey.inc";
            var clientId = "5fed92eb-46d1-4689-af60-1a8e679fd539";
            var clientSecret = "2a13febb-1e3d-4532-8f40-cd426def2b93";
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

