package com.heybanco.baas.consumer;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
 * This class provides methods for generating an authorization token, sending
 * HTTP requests,
 * signing and encrypting payloads, and decrypting and verifying signed
 * payloads.
 */
public class SecurityManager {
    private JWK jwkPublicRSA;
    private JWK jwkPrivateRSA;
    private static final String TOKEN_URL = "https://test-tech.hey.inc/api-auth/v1/oidc/token";
    private static final String HTTP_METHOD = "POST";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String SSL_PROTOCOL = "TLS";
    private static final String OAUTH_GRAN_TYPE_VALUE = "client_credentials";
    private static final String OAUTH_GRAN_TYPE = "grant_type";
    private static final String OAUTH_CLIENT_ID = "client_id";
    private static final String OAUTH_CLIENT_SECRET = "client_secret";
    private static final String EQUALS_SING = "=";
    private static final String AMPERSAND = "&";
    private static final String KEYSTORE_PATH_VALUE = "KEYSTORE_PATH";
    private static final String KEYSTORE_PASSWORD_VALUE = "KEYSTORE_PASSWORD";
    private static final String PRIVATEKEY_VALUE = "PRIVATEKEY";
    private static final String PUBLICKEY_VALUE = "PUBLICKEY";
    private static final String HEADER_KEY = "Content-Type";
    private static final String HEADER_VALUE = "application/x-www-form-urlencoded";

    private final Properties properties;

    /**
     * Builds an SecurityManager object with the specified Properties object.
     * 
     * @param properties the Properties object to be used by the SecurityManager
     */
    public SecurityManager(Properties properties) {
        this.properties = properties;
    }

    /**
     * Generates an authorization token using client credentials grant type.
     * This method makes a POST request to a specified token URL with the client ID
     * and client secret.
     * 
     * @param clientId     The client ID for authentication.
     * @param clientSecret The client secret for authentication.
     * @return the authorization token.
     * @throws IOException               if an I/O error occurs while making the
     *                                   request.
     * @throws UnrecoverableKeyException if the key in the keystore cannot be
     *                                   recovered.
     * @throws CertificateException      if there is an error with the certificate.
     * @throws KeyStoreException         if there is an error with the keystore.
     * @throws NoSuchAlgorithmException  if the algorithm used for the SSL context
     *                                   is not available
     * @throws KeyManagementException    if there is an error with the SSL context.
     * @throws URISyntaxException        if there is an error with the URI syntax.
     * @throws InterruptedException      if the thread is interrupted.
     */
    public String getAuthorizationToken(String clientId, String clientSecret)
            throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException,
            NoSuchAlgorithmException, KeyManagementException, URISyntaxException, InterruptedException {
        String requestBody = OAUTH_GRAN_TYPE + EQUALS_SING + OAUTH_GRAN_TYPE_VALUE
                + AMPERSAND + OAUTH_CLIENT_ID + EQUALS_SING + clientId
                + AMPERSAND + OAUTH_CLIENT_SECRET + EQUALS_SING + clientSecret;
        Map<String, String> headers = new HashMap<>();
        headers.put(HEADER_KEY, HEADER_VALUE);
        HttpClient httpClient = HttpClient.newBuilder()
                .sslContext(getSSLContext())
                .build();
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(new URI(TOKEN_URL))
                .method(HTTP_METHOD, HttpRequest.BodyPublishers.ofString(requestBody));
        headers.forEach(requestBuilder::header);
        HttpResponse<String> response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        return response.body();
    }

    /**
     * Obtains an SSL context with the specified key store and password.
     * 
     * @return the SSL context
     * @throws KeyStoreException         if there is an error with the key store
     * @throws IOException               if there is an error with the input/output
     *                                   operations
     * @throws UnrecoverableKeyException if the key in the keystore cannot be
     *                                   recovered.
     * @throws CertificateException      if there is an error with the certificate.
     * @throws KeyStoreException         if there is an error with the keystore.
     * @throws NoSuchAlgorithmException  if the algorithm used for the SSL context
     *                                   is not available
     * @throws KeyManagementException    if there is an error with the SSL context.
     */
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

    /**
     * Signs and encrypts the payload using RSA 256 algorithm.
     * 
     * @param requestPayload the payload to be signed and encrypted
     * @param bApplication   the key ID used for signing and encrypting the payload
     * @return the signed and encrypted payload as a string
     * @throws IOException   if an I/O error occurs while reading the key files
     * @throws JOSEException if an error occurs while parsing the keys
     *
     */
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

    /**
     * decrypts and verifies the signature of a JWE/JWS payload.
     * 
     * @param requestPayload the JWE/JWS payload to be decrypted and verified
     * @return the decrypted and verified payload or an empty string if the
     *         signature
     * @throws JOSEException  if an error occurs while parsing the keys
     * @throws IOException    if an I/O error occurs while reading the key files
     * @throws ParseException if the payload is not in the expected format
     */
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

    /**
     * Parses the private and public keys in PEM format and sets them as JWK
     * objects.
     * 
     * @throws IOException   if an I/O error occurs while reading the key files
     * @throws JOSEException if an error occurs while parsing the keys
     */
    private void loadKeys() throws IOException, JOSEException {
        jwkPrivateRSA = JWK.parseFromPEMEncodedObjects(readFile(this.properties.getProperty(PRIVATEKEY_VALUE)));
        jwkPublicRSA = JWK.parseFromPEMEncodedObjects(readFile(this.properties.getProperty(PUBLICKEY_VALUE)));
    }

    /**
     * Reads the content of a file as a string.
     * 
     * @param filePath the path to the file to read
     * @return the content of the file as a string
     * @throws IOException if an I/O error occurs while reading the file
     */
    private static String readFile(String filePath) throws IOException {
        return Files.readString(Path.of(filePath));
    }

}
