# APIClient Module Readme

## Description
This module exports the APIClient class, which provides a simple way to make HTTP requests to an API using OAuth 2.0 authentication with client credentials grant flow and encrypted payloads.

## Installation

To use the APIClient module, you need to have Node.js and NPM installed. Then, you can install the module by running the following command:

```javascript
npm install
```
## Usage

To use the APIClient module, you need to instantiate a new APIClient object, and then use its methods to make requests to the API.
Creating an APIClient Object

To create an APIClient object, you need to require the APIClient module and create a new instance of the APIClient class:
```javascript
const APIClient = require('./APIClient.js');
const client = new APIClient();
```
## Generating an Authorization Token

Before you can make requests to the API, you need to generate an authorization token. You can do this by calling the getAuthorizationToken method on your APIClient object:

```javascript
client.getAuthorizationToken().then((accessToken) => {
  // Use the access token to make requests to the API
}).catch((error) => {
  console.error(error);
});
```
## Making a Request to the API

Once you have an access token, you can use it to make requests to the API. To make a request, you need to call the makeRequest method on your APIClient object, and pass in the endpoint, method, request payload, and headers for the API request:

```javascript
const endpoint = '/accounts';
const http_method = 'POST';
const requestPayload = '';

const headers = {
  'Accept': 'application/json',
  'Content_Type': 'application/json',
  'B_Transaction': '12345678',
  'Accept_Charset': 'UTF-8'
};

client.makeRequest(endpoint, http_method, requestPayload, headers)
  .then((response) => {
    console.log(response);
  })
  .catch((error) => {
    console.error(error);
  });

```
# Module Security Manager

## Description
This module provides methods for signing and encrypting payloads, as well as decrypting and verifying signed payloads. It uses the jose library to handle encryption, decryption, and signing.

## Dependencies
To use this module, you must first install the required dependencies:
```javascript
npm install jose
npm install fs
npm install rsa-pem-to-jwk
npm install dotenv

```
## Usage

To use the functions provided by this module, you need to import it into your code as follows:
```javascript
const securityManager = require('./SecurityManager.js');

```
## signAndEncryptPayload

This function takes a payload as a string, signs it, and then encrypts it using the provided public key. It returns the signed and encrypted payload as a string.

```javascript
    const signedEncryptedPayload = await securityManager.signAndEncryptPayload(payload);
```
## decryptAndVerifySignPayload

This function takes a signed and encrypted payload as a string, decrypts it, and verifies its signature. It returns the decrypted and verified payload as a string.

```javascript
const decryptedVerifiedPayload = await securityManager.decryptAndVerifySignPayload(signedEncryptedPayload);
```

## .env file

This module reads the private and public key paths and application id from the .env file. The .env file should have the following structure:

    CERT_PATH: This key specifies the path to the mTLS certificate file file in the APIConsumer project.  
    PRIVATE_KEY_PATH= This key specifies the path to the client private key file in the APIConsumer project. 
    PUBLIC_KEY_PATH: This key specifies the path to the server public key file in the APIConsumer project. 
    HOSTNAME: Defines the hostname of the remote server.
    OAUTH_CLIENT_ID: The client ID used to authenticate with the remote server.
    OAUTH_CLIENT_SECRET: The client secret used to authenticate with the remote server.
    B_APPLICATION: Unique consumer application identifier, used to sign and encrypt the payload.

These properties are used by the APIConsumer project.

## Create PEM Certificates

Extract the security kit in the path, it is recommended to use the resources path of this project. Then I ran the following commands to convert the certificates sent to pem.

```openssl

  openssl pkcs12 -in Client_KeyStore_test_16723f8c-e2a6-4dd3-a663-572c4a255e69.p12  -nokeys -out cert.pem
  openssl rsa -passin pass:Password -in Client_test_16723f8c-e2a6-4dd3-a663-572c4a255e69.key > Client_test_16723f8c-e2a6-4dd3-a663-572c4a255e69.pem
  ```