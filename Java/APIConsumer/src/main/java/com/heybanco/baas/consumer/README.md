# Security Manager Class Readme

# Description
The SecurityManager class is part of the com.heybanco.baas.consumer package and provides methods for generating an authorization token, sending HTTP requests, signing and encrypting payloads, and decrypting and verifying signed payloads.

# Dependencies

This class depends on the following external libraries:

    com.nimbusds:nimbus-jose-jwt:9.30.2
    org.bouncycastle:bcpkix-jdk15on:1.50
    Java HTTP Client version 11.0.2

# Constructors

SecurityManager(Properties properties)

Builds an SecurityManager object with the specified Properties object.
```java
	public SecurityManager(Properties properties)

```
**Parameters**

    properties: the Properties object to be used by the SecurityManager.

# Public Methods

**getAuthorizationToken(String clientId, String clientSecret)**

Generates an authorization token using client credentials grant type. Makes a POST request to a specified token URL with the client ID and client secret.
```java
public String getAuthorizationToken(String clientId, String clientSecret) throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException, URISyntaxException, InterruptedException
```
**Parameters**

        clientId: the client ID to use for the request
        clientSecret: the client secret to use for the request
        
**Exceptions**

        throws IOException if an I/O error occurs while making the request.
        throws UnrecoverableKeyException if the key in the keystore cannot be recovered.
        throws CertificateException if there is an error with the certificate.
        throws KeyStoreException if there is an error with the keystore.
        throws NoSuchAlgorithmException if the algorithm used for the SSL context is not available.
        throws KeyManagementException if there is an error with the SSL context.
**Returns**
        
        returns the authorization token

**getSSLContext()**

Obtains an SSL context with the specified key store and password.
```jjava

public SSLContext getSSLContext() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException
```

**Exceptions**

    KeyStoreException: if there is an error with the key store.
    IOException: if there is an error with the input/output operations.
    UnrecoverableKeyException: if the key in the keystore cannot be recovered.
    CertificateException: if there is an error with the certificate.
    KeyStoreException: if there is an error with the keystore.
    NoSuchAlgorithmException: if the algorithm used for the SSL context is not available.
    KeyManagementException: if there is an error with the SSL context.

**Returns**
The SSL context.


 