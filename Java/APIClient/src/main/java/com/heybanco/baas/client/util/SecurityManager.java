package com.heybanco.baas.client.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Base64;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * This class provides methods for generating an authorization token, sending
 * HTTP requests,
 * signing and encrypting payloads, and decrypting and verifying signed
 * payloads.
 */
public class SecurityManager {
    private static final Logger logger = Logger.getLogger(SecurityManager.class.getName());
    private JWK jwkPublicRSA;
    private JWK jwkPrivateRSA;

    private final Properties properties;
    private static final String B_APPLICATION_VALUE = "SUBSCRIPTION_B_APPLICATION";
    private static final String MTLS_KEYSTORE_PATH = "MTLS_KEYSTORE_PATH";
    private static final String MTLS_KEYSTORE_PASSWD = "MTLS_KEYSTORE_PASSWD";
    private static final String JWE_SERVER_PUBLICKEY = "JWE_SERVER_PUBLICKEY";

    /**
     * Builds an SecurityManager object needed to establish a secure HTTP connection
     * through mTLS flow.
     * 
     * @param properties the Properties object to be used by the SecurityManager
     */
    public SecurityManager(Properties properties) {
        this.properties = properties;
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
        final String KEYSTORE_TYPE = "PKCS12";
        final String SSL_CONTEXT_TYPE = "TLSv1.2";

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(new FileInputStream(this.properties.getProperty(MTLS_KEYSTORE_PATH)),
                this.properties.getProperty(MTLS_KEYSTORE_PASSWD).toCharArray());
        KeyManagerFactory keyManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManager.init(keyStore, this.properties.getProperty(MTLS_KEYSTORE_PASSWD).toCharArray());
        SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT_TYPE);
        sslContext.init(keyManager.getKeyManagers(), null, null);

        loadKeys(keyStore);

        return sslContext;
    }

    /**
     * Signs and encrypts the payload using RSA 256 algorithm.
     * 
     * @param requestPayload the payload to be signed and encrypted
     * @param bApplication   the key ID used for signing and encrypting the payload
     * @throws IOException   if an I/O error occurs while reading the key files
     * @throws JOSEException if an error occurs while parsing the keys
     * @return The structured signed and encrypted payload as a string
     */
    public String signAndEncryptPayload(String requestPayload, String bApplication) throws IOException, JOSEException {
        logger.log(Level.INFO, "Encrypting and Signing request payload ...");
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(bApplication).build();
        Payload jwsPayload = new Payload(requestPayload);
        JWSObject jwsObject = new JWSObject(jwsHeader, jwsPayload);
        jwsObject.sign(new RSASSASigner(jwkPrivateRSA.toRSAKey()));
        JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .keyID(bApplication).build();
        JWEObject jweObject = new JWEObject(jweHeader, new Payload(jwsObject.serialize()));
        jweObject.encrypt(new RSAEncrypter(jwkPublicRSA.toRSAKey().toPublicJWK()));
        return  "{\"data\":\"" + jweObject.serialize() + "\"}";
    }

    /**
     * decrypts and verifies the signature of a JWE/JWS payload.
     * 
     * @param responsePayload the JWE/JWS payload to be decrypted and verified
     * @return the decrypted and verified payload or an empty string if the
     *         signature
     * @throws JOSEException  if an error occurs while parsing the keys
     * @throws IOException    if an I/O error occurs while reading the key files
     * @throws ParseException if the payload is not in the expected format
     *
     */
    public String decryptAndVerifySignPayload(String responsePayload) throws IOException, ParseException, JOSEException {
        logger.log(Level.INFO, "Decrypting and Verifying signature request payload ...");
        JWEObject jweObject = JWEObject.parse(responsePayload);
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
     */
    private void loadKeys(KeyStore keyStore) {
        try {
            jwkPublicRSA = JWK.parseFromPEMEncodedObjects(
                    Files.readString(Path.of(this.properties.getProperty(JWE_SERVER_PUBLICKEY))));

            final Key key = keyStore.getKey(this.properties.getProperty(B_APPLICATION_VALUE), this.properties.getProperty(MTLS_KEYSTORE_PASSWD).toCharArray());

            final String BEGIN_CERT = "-----BEGIN PRIVATE KEY-----";
            final String END_CERT = "-----END PRIVATE KEY-----";
            final String LINE_SEPARATOR = System.getProperty("line.separator");
            final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());
            final byte[] rawCrtText = key.getEncoded();
            final String encodedCertText = new String(encoder.encode(rawCrtText));
            final String prettified_cert = BEGIN_CERT + LINE_SEPARATOR + encodedCertText + LINE_SEPARATOR + END_CERT;

            jwkPrivateRSA = JWK.parseFromPEMEncodedObjects(prettified_cert);

        } catch (IOException | JOSEException | RuntimeException | KeyStoreException | NoSuchAlgorithmException |
                 UnrecoverableKeyException ex) {
            logger.log(Level.WARNING, "Exception: ", ex);
        }
    }

}
