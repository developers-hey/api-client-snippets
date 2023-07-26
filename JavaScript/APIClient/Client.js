/**

    This module exports the Client class, which is used to make HTTP requests
    to an API using OAuth 2.0 authentication with client credentials grant flow
    and encrypted payloads.
    @module APIClient
    */
const request = require('request');
const securityManager = require('./SecurityManager.js');
const dotenv = require('dotenv');
const fs = require('fs');
dotenv.config();

/**

    The certificate and private key files are read and stored in memory
    for later use in HTTPS requests.
    @constant {string} CERT_PATH - The path to the certificate file.
    @constant {string} PRIVATE_KEY_PATH - The path to the private key file.
    */
const CERT = fs.readFileSync(process.env.CERT_PATH);
const PRIVATE_KEY = fs.readFileSync(process.env.PRIVATE_KEY);
const HEADER_KEY = 'Content-Type';
const HEADER_VALUE = 'application/x-www-form-urlencoded';

class Client {
  constructor() {
    this.basePath =  process.env.BASE_PATH
    this.clientId = process.env.CLIENT_ID;
    this.clientSecret = process.env.CLIENT_SECRET;
    this.accessToken = null;

  }

  /**

     Generates an authorization token using client credentials grant type.
     This method makes a POST request to a specified token URL with the client ID and client secret.
    @function getAuthorizationToken
    @async
    @returns {Promise<string>} - A promise that resolves with the access token string.
    */

  getAuthorizationToken() {
    const options = {
      url: process.env.HOSTNAME_DNS + process.env.OAUTH_URI_NAME,
      method: process.env.HTTP_VERB,
      headers: {
        'Content-Type': HEADER_VALUE,
      },
      form: {
        grant_type: process.env.OAUTH_GRANT_TYPE,
        client_id: this.clientId,
        client_secret: this.clientSecret,
      }, agentOptions: {
        key: PRIVATE_KEY,
        cert: CERT,
      },
    };

    return new Promise((resolve, reject) => {
      request(options, (error, response, body) => {
        if (error) {
          reject(error);
        } else {
          const data = JSON.parse(body);
          this.accessToken = data.access_token;
          resolve(data.access_token);
        }
      });
    });
  }

  /**

    Makes a request to the API using the provided parameters and the access token.
    @function makeRequest
    @async
    @param {string} endpoint - The endpoint for the API request.
    @param {string} method - The HTTP method for the API request.
    @param {Object|null} body - The request body for the API request, if any.
    @param {Object} headers - The headers for the API request.
    @returns {Promise<Object>} - A promise that resolves with the response body object.
    */
  async makeRequest(endpoint, method = 'POST', body = null, headers) {
    if (!this.accessToken) {
      await this.getAuthorizationToken();
    }
    let signedEncryptedPayloadJson = null;
    if (body) {
      const signedEncryptedPayload = await securityManager.signAndEncryptPayload(body);
      signedEncryptedPayloadJson = { data: signedEncryptedPayload }
    }

    const options = {
      url: process.env.HOSTNAME_DNS + `${this.basePath}${endpoint}`,
      method,
      headers: {
        Accept: headers.Accept,
        'Content-Type': headers.Content_Type,
        'B-Transaction': headers.B_Transaction,
        'Accept-Charset': headers.Accept_Charset,
        'B-application': process.env.B_APPLICATION,
        Authorization: `Bearer ${this.accessToken}`,
      }, agentOptions: {
        key: PRIVATE_KEY,
        cert: CERT,
      },
      json: signedEncryptedPayloadJson ? signedEncryptedPayloadJson : true,
    };

    return new Promise((resolve, reject) => {
      request(options, (error, response, body) => {
        if (error) {
          reject(error);
        } else {
          resolve(response);
        }
      });
    });
  }


}

/* 
Example implement Client

*/
const client = new Client();

const headers = {
  'Accept': process.env.MIME_TYPE ,
  'Content_Type': process.env.MIME_TYPE,
  'B_Transaction': process.env.B_TRANSACTION,
  'Accept_Charset': process.env.ENCODE_CHARSET
};

client.getAuthorizationToken().then((accessToken) => {
  console.log(accessToken);
 client.makeRequest(process.env.URI_NAME, process.env.HTTP_VERB , process.env.UNENCRYPTED_PAYLOAD, headers)
    .then((response) => {
      console.log(response.headers);
      console.log(response.body);
      if (response.headers.location) {
        const headers = {
          'Accept': process.env.MIME_TYPE ,
          'B_Transaction': process.env.B_TRANSACTION,
          'Accept_Charset': process.env.ENCODE_CHARSET
        };
        client.makeRequest(endpoint, 'GET', null, headers)
          .then(async (response) => {
            console.log(response.headers);
            console.log(response.body);
            if (response.body.data) {
              const decryptedVerifiedPayload = await securityManager.decryptAndVerifySignPayload(response.body.data);
              console.log(decryptedVerifiedPayload);
            }

          })
          .catch((error) => {
            console.error(error);
          });


      }
    })
    .catch((error) => {
      console.error(error);
    });
}).catch((error) => {
  console.error(error);
});
