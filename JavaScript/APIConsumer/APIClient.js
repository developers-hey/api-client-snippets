/**

    This module exports the APIClient class, which is used to make HTTP requests
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
    @constant {string} CERT - The path to the certificate file.
    @constant {string} PRIVATE_KEY - The path to the private key file.
    */
const CERT = fs.readFileSync(process.env.CERT);
const PRIVATE_KEY = fs.readFileSync(process.env.PRIVATE_KEY);

const TOKEN_ENDPOINT = '/auth/v1/oidc/token'
const HTTP_METHOD = 'POST';
const HEADER_KEY = 'Content-Type';
const HEADER_VALUE = 'application/x-www-form-urlencoded';
const OAUTH_GRANT_TYPE_VALUE = 'client_credentials';


class APIClient {
  constructor() {
    this.basePath = '/taas/v1.0';
    this.clientId = process.env.OAUTH_CLIENT_ID;
    this.clientSecret = process.env.OAUTH_CLIENT_SECRET;
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
      url: process.env.HOSTNAME + TOKEN_ENDPOINT,
      method: HTTP_METHOD,
      headers: {
        'Content-Type': HEADER_VALUE,
      },
      form: {
        grant_type: OAUTH_GRANT_TYPE_VALUE,
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


    const signedEncryptedPayload = await securityManager.signAndEncryptPayload(body);
    const options = {
      url: process.env.HOSTNAME + `${this.basePath}${endpoint}`,
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
      json: { data: signedEncryptedPayload },
    };

    return new Promise((resolve, reject) => {
      request(options, (error, response, body) => {
        if (error) {
          reject(error);
        } else {
          resolve(body);
        }
      });
    });
  }


}

/* 
Example implement APIClient

*/
const client = new APIClient();
var endpoint = '/accounts';
var http_method = 'POST';
var requestPayload = '{\"taxRegimeId\": 2,\"name\": \"Jose Luis\",\"lastName\": \"Lemus\",\"secondLastName\": \"Valdivia\",\"businessName\": \"\",\"birthday\": \"1996-10-03\",\"rfc\": \"LEVL961003KQ0\",\"curp\": \"LEVL961003HBSMLS06\",\"callingCode\": \"52\",\"cellPhoneNumber\": \"3311065681\",\"email\": \"jose.lemus@banregio.com\",\"nationalityId\": \"001\",\"countryId\": \"01\",\"stateId\": \"047\",\"cityId\": \"04701005\",\"legalRepresentative\": {\"name\": \"\",\"lastName\": \"\",\"secondLastName\": \"\"}}';
const headers = {
  'Accept': 'application/json',
  'Content_Type': 'application/json',
  'B_Transaction': '12345678',
  'Accept_Charset': 'UTF-8'
};

client.getAuthorizationToken().then((accessToken) => {
  client.makeRequest(endpoint, http_method, requestPayload, headers)
    .then((response) => {
      console.log(response);
      
    })
    .catch((error) => {
      console.error(error);
    });
}).catch((error) => {
  console.error(error);
});





