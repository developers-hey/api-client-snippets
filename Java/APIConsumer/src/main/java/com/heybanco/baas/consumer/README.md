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

**getAuthorizationToken()**

Generates an authorization token using client credentials grant type. Makes a POST request to a specified token URL with the client ID and client secret.
```java
public String getAuthorizationToken() throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException, URISyntaxException, InterruptedException
```
        
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
```java

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

# APIConsumer Class

The ApiConsumer class is a Java class that consumes an API from a remote server. It includes various properties and methods to make HTTP requests, handle security, and process response data.

# Properties

The class has the following properties:

    logger: A logger object that is used for logging messages.
  
 # Methods

The class has a main method that serves as the entry point of the application. It uses various helper methods to perform the following tasks:

    Load configuration properties from a file.
    Retrieve an authorization token from the remote server.
    Create HTTP headers and payload for the API request.
    Sign and encrypt the payload using the B-application.
    Send a POST request to create an account.
    Extract the account ID from the response headers.
    Send a GET request to retrieve the account data.
    Decrypt and verify the signed payload in the response data.

# File Config
This repository contains a file named **config.properties** that contains key-value pairs for the APIConsumer project. These properties are used for authentication and encryption purposes.

# Usage

The properties file contains the following keys:

    KEYSTORE_PATH: This key specifies the path to the client keystore file in the APIConsumer project. 
    KEYSTORE_PASSWORD: This key specifies the password for the client keystore file. 
    PRIVATEKEY: This key specifies the path to the client private key file in the APIConsumer project. 
    PUBLICKEY: This key specifies the path to the server public key file in the APIConsumer project. 
    HOSTNAME: Defines the hostname of the remote server.
    OAUTH_CLIENT_ID: The client ID used to authenticate with the remote server.
    OAUTH_CLIENT_SECRET: The client secret used to authenticate with the remote server.
    B_APPLICATION: Unique consumer application identifier, used to sign and encrypt the payload.

    
These properties are used by the APIConsumer project.