package com.heybanco.baas.consumer;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import java.io.IOException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * This class provides methods for generating an authorization token, sending HTTP requests,
 * signing and encrypting payloads, and decrypting and verifying signed payloads.
 */
public class APIConsumer {
    private   JWK jwkPublicRSA;
    private  JWK jwkPrivateRSA;
    private  static final String TOKEN_ENDPOINT = "https://test-tech.hey.inc/api-auth/v1/oidc/token";
    private  static final String HTTP_METHOD = "POST";
    private  static final  String KEYSTORE_TYPE = "PKCS12";
    private  static final  String SSL_PROTOCOL = "TLS";
    private   final Properties properties;

    /**
     Constructs an APIConsumer object with the specified Properties object.
     @param properties the Properties object to be used by the APIConsumer
     */
    public APIConsumer(Properties properties) {
        this.properties = properties;
    }

    /**
     Generates an authorization token using client credentials grant type.
     This method makes a POST request to a specified token URL with the client ID and client secret.
     @param clientId The client ID for authentication.
     @param clientSecret The client secret for authentication.
     @return the authorization token.
     @throws IOException if an I/O error occurs while making the request.
     @throws UnrecoverableKeyException if the key in the keystore cannot be recovered.
     @throws CertificateException if there is an error with the certificate.
     @throws KeyStoreException if there is an error with the keystore.
     @throws NoSuchAlgorithmException if the algorithm used for the SSL context is not
     @throws KeyManagementException if there is an error with the SSL context.
     */
    public String getAuthorizationToken(String clientId, String clientSecret) throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        String requestBody = "grant_type=client_credentials"
                + "&client_id=" + clientId
                + "&client_secret=" + clientSecret;
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        return  sendRequest(HTTP_METHOD, TOKEN_ENDPOINT,headers  ,requestBody,null,null);
    }

    /**
     Sends a HTTP request to the specified endpoint with the given headers and body.
     @param method the HTTP method to use (GET, POST, PUT, DELETE, etc.)
     @param endpoint the URL of the API endpoint to call
     @param headers the headers to send in the request
     @param body the body of the request (can be null)
     @param queryParams a Map of query parameters to include in the request URL
     @param pathParams a Map of path parameters to substitute in the request URL
     @return the HTTP response from the server
     @throws IOException if an I/O error occurs during the request
     */
    public  String sendRequest(String method, String endpoint, Map<String, String> headers,String body, Map<String, String> queryParams, Map<String, String> pathParams) throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {

        if (queryParams != null) {
            StringBuilder queryString = new StringBuilder();
            for (Map.Entry<String, String> entry : queryParams.entrySet()) {
                if (queryString.length() > 0) {
                    queryString.append("&");
                }
                queryString.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
                queryString.append("=");
                queryString.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
            }
            endpoint += "?" + queryString.toString();
        }
        if (pathParams != null && !pathParams.isEmpty()) {
            for (Map.Entry<String, String> entry : pathParams.entrySet()) {
                endpoint = endpoint.replace("{" + entry.getKey() + "}", entry.getValue());
            }
        }
        URL url = new URL(endpoint);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setSSLSocketFactory(getSSLContext().getSocketFactory());
        connection.setRequestMethod(method);

        for (Map.Entry<String, String> entry : headers.entrySet()) {
            connection.setRequestProperty(entry.getKey(), entry.getValue());
        }
        if (body != null) {
            connection.setDoOutput(true);
            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = body.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }
        }
        try (BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder response = new StringBuilder();
            String responseLine = null;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
            return response.toString();
        }
    }

    /**
     Obtains an SSL context with the specified key store and password.
     @return the SSL context
     @throws KeyStoreException if there is an error with the key store
     @throws IOException if there is an error with the input/output operations
     @throws CertificateException if there is an error with the certificate
     @throws NoSuchAlgorithmException if there is an error with the algorithm
     @throws UnrecoverableKeyException if there is an error with the key
     @throws KeyManagementException if there is an error with the key management
     */
    private   SSLContext getSSLContext() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {

        KeyStore clientKeyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        clientKeyStore.load( new FileInputStream(this.properties.getProperty("KEYSTORE_PATH")), this.properties.getProperty("KEYSTORE_PASSWORD") .toCharArray());
        KeyManagerFactory keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManager.init(clientKeyStore, this.properties.getProperty("KEYSTORE_PASSWORD").toCharArray());
        SSLContext sslContext = SSLContext.getInstance(SSL_PROTOCOL);
         sslContext.init(keyManager.getKeyManagers(), null, null);
        return sslContext;
    }

    /**
     * Signs and encrypts the payload using RSA 256 algorithm.
     * @param requestPayload the payload to be signed and encrypted
     * @param bApplication the key ID used for signing and encrypting the payload
     * @return the string
     */
    public String signAndEncryptPayload(String requestPayload , String bApplication) throws IOException, JOSEException {
        startKeys();
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

    /**
     * decrypts and verifies the signature of a JWE/JWS payload.
     * @param requestPayload the JWE/JWS payload to be decrypted and verified
     * @return the string
     */
    public String decryptAndVerifySignPayload(String requestPayload) throws IOException, ParseException, JOSEException {
        startKeys();
        JWEObject jweObject = JWEObject.parse( requestPayload);
        JWEDecrypter decrypter = new RSADecrypter(jwkPrivateRSA.toRSAKey());
        jweObject.decrypt(decrypter);
        String  strDecrypt = jweObject.getPayload().toString();
        JWSObject jwsObject = JWSObject.parse(strDecrypt);
        JWSVerifier verifier = new RSASSAVerifier(jwkPublicRSA.toRSAKey().toPublicJWK());
        return jwsObject.verify(verifier) ? jwsObject.getPayload().toString() : "";
    }

    /**
     Parses the private and public keys in PEM format and sets them as JWK objects.
     @throws IOException if an I/O error occurs while reading the key files
     @throws JOSEException if an error occurs while parsing the keys
     */
    private  void startKeys() throws IOException, JOSEException {
        jwkPrivateRSA = JWK.parseFromPEMEncodedObjects(readFile(this.properties.getProperty("PRIVATEKEY")));
        jwkPublicRSA = JWK.parseFromPEMEncodedObjects(readFile(this.properties.getProperty("PUBLICKEY")));
    }
    /**
     Reads the content of a file as a string.
     @param filePath the path to the file to read
     @return the content of the file as a string
     @throws IOException if an I/O error occurs while reading the file
     */
    private static String readFile(String filePath) throws IOException {
        return Files.readString(Path.of(filePath));
    }

}
