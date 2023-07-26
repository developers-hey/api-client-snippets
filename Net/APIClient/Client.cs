using System;
using Newtonsoft.Json.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;


namespace ApiClient
{
    class Client
    {
        
        static async Task Main(string[] args)
        {
            IConfiguration configuration = new ConfigurationBuilder()
            .AddJsonFile("/resources/appsettings.json")
            .Build();
            var endpoint = configuration["api:uri.name"];
            var basePath = configuration["api:base.path"];
            var hostname = configuration["api:hostname.dns"]; 
            var clientId = configuration["subscription:client.id"];
            var clientSecret = configuration["subscription:client.secret"];
            var requestBody = configuration["request:unencrypted.payload"];
                
            var apiClient = new SecurityManager(hostname, clientId, clientSecret);
            var token = await apiClient.GetAccessTokenAsync();
            var signedEncryptedPayload = apiClient.SignAndEncryptPayload(requestBody);
            var signedEncryptedPayloadJson = "{\"data\":\"" + signedEncryptedPayload + "\"}";
            var response = await apiClient.MakeApiRequestAsync(
                basePath + endpoint,
                token,
                configuration["request:http.verb"],
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

