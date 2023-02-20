APIConsumer Class Readme

Description
The APIConsumer class provides methods for generating an authorization token, sending HTTP requests, signing and encrypting payloads, and decrypting and verifying signed payloads.

Constructors
   public APIConsumer(Properties properties): 
Creates a new APIConsumer object with the specified properties.


Public Methods

    String getAuthorizationToken(String clientId, String clientSecret):
    Generates an authorization token using client credentials grant type. Makes a POST request to a specified token URL with the client ID and client secret.
        clientId: the client ID to use for the request
        clientSecret: the client secret to use for the request
        returns the authorization token
        throws IOException if an I/O error occurs while making the request.
        throws UnrecoverableKeyException if the key in the keystore cannot be recovered.
        throws CertificateException if there is an error with the certificate.
        throws KeyStoreException if there is an error with the keystore.
        throws NoSuchAlgorithmException if the algorithm used for the SSL context is not available.
        throws KeyManagementException if there is an error with the SSL context.

    String sendRequest(String method, String endpoint, Map<String, String> headers, String body):
        Sends a HTTP request to the specified endpoint with the given headers and body.
        method: the HTTP method to use (GET, POST, PUT, DELETE, etc.)
        endpoint: the URL of the API endpoint to call
        headers: the headers to send in the request
        body: the body of the request (can be null)
        queryParams a Map of query parameters to include in the request URL
        pathParams a Map of path parameters to substitute in the request URL
        returns the HTTP response from the server
        throws IOException if an I/O error occurs during the request
        throws UnrecoverableKeyException if the key in the keystore cannot be recovered.
        throws CertificateException if there is an error with the certificate.
        throws KeyStoreException if there is an error with the keystore.
        throws NoSuchAlgorithmException if the algorithm used for the SSL context is not available.
        throws KeyManagementException if there is an error with the SSL context.

    String signAndEncryptPayload(String requestPayload , String bApplication):
       Sign and encrypt payload string.
        requestPayload: the payload string to sign and encrypt
        bApplication: the application to use for signing and encrypting
        returns the signed and encrypted payload string
        throws IOException if an I/O error occurs during the request
        throws JOSEException if there is an error with the signing or encryption process.

    String decryptAndVerifySignPayload(RequestModel model): Decrypt and verify sign payload string.
        model: the request model containing the payload string to decrypt and verify
        returns the decrypted and verified payload string
        throws IOException if an I/O error occurs during the request
        throws ParseException if there is an error parsing the payload string
        throws JOSEException if there is an error with the decryption or verification process.