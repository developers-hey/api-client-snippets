using System.Text;
using System.Security.Cryptography.X509Certificates;
using Jose;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;

namespace ApiClient
{
    public class SecurityManager
    {
        private readonly IConfigurationRoot configuration;
        /**
          * Constructs a SecurityManager object with the specified parameters.
          * @param configuration the configuration object    
        **/
        public SecurityManager(IConfigurationRoot configuration)
        {
            this.configuration = configuration;
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
                configuration["MTLS:KEYSTORE_PATH"],
                configuration["MTLS:KEYSTORE_PASSWD"]
            ).GetRSAPrivateKey();
            var publicKey = File.ReadAllText(configuration["JWE:SERVER_PUBLICKEY"], Encoding.UTF8);
            RSA rsaPublic = LoadRsaKey(publicKey);
            var headers = new Dictionary<string, object>() { { "kid", configuration["SUBSCRIPTION:B_APPLICATION"] } };
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
                configuration["MTLS:KEYSTORE_PATH"],
                configuration["MTLS:KEYSTORE_PASSWD"]
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
    }
}
