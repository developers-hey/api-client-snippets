/**
    This module exports the Client class, which is used to make HTTP requests
    to an API using OAuth 2.0 authentication with client credentials grant flow
    and encrypted payloads.
    @module APIClient
    */
const request = require('request');
const securityManager = require('./util/security-manager.js');
const dotenv = require('dotenv');

const fs = require('fs');



class Client {
  constructor() {}

  async main() {
    dotenv.config();
    this.getToken().then((token) => {
      const headers = {
        'Authorization': token,
        'B-Application': process.env.SUBSCRIPTION_B_APPLICATION,
        'B-Transaction': process.env.REQUEST_B_TRANSACTION,
        'B-Option': process.env.REQUEST_B_OPTION,
        'Content-Type': process.env.REQUEST_MIME_TYPE,
        'Accept': process.env.REQUEST_MIME_TYPE,
        'Accept-Charset': process.env.REQUEST_ENCODE_CHARSET
      };

      const apiEndpoint = process.env.API_HOST_DNS + process.env.API_BASE_PATH + process.env.API_RESOURCE_NAME;
      this.doRequest(process.env.REQUEST_HTTP_VERB, apiEndpoint, process.env.REQUEST_UNENCRYPTED_PAYLOAD, headers, process.env.REQUEST_SEND_PAYLOAD, process.env.REQUEST_SEND_PAYLOAD);
    });
  }


  /**
    Makes a request to the API using the provided parameters and the access token.
    @function doRequest
    @async
    @param {string} httpVerb - The HTTP method for the API request.
    @param {string} endpoint - The endpoint for the API request.
    @param {Object|null} requestPayload - The request body for the API request, if any.
    @param {Object} headers - The headers for the API request.
    @param {Object} sendPayload - Flag to indicate if the request must to include the body.
    @param {Object} payloadEncryption - Flag to indicate if is required encryption for the request payload.
    @returns {Promise<Object>} - A promise that resolves with the response body object.
    */
  async doRequest(httpVerb, endpoint, requestPayload, headers, sendPayload, payloadEncryption) {
    console.log("===============================================================")
    console.log(`Request ${httpVerb}: ${endpoint}`)
    console.log(`Headers: [${JSON.stringify(headers)}]`)
    const success_response_200 = 200
    const success_response_201 = 201
    const b_trace_header = "b-trace"
    const location_header = "location"
    let responsePayload = ""
    const clientPrivateKey = securityManager.convertP12ToPem(process.env.MTLS_KEYSTORE_PATH, process.env.MTLS_KEYSTORE_PASSWD, true)
    const clientPublicKey = securityManager.convertP12ToPem(process.env.MTLS_KEYSTORE_PATH, process.env.MTLS_KEYSTORE_PASSWD, false)

    if (sendPayload && payloadEncryption) {
      await securityManager.signAndEncryptPayload(requestPayload, process.env.SUBSCRIPTION_B_APPLICATION, clientPrivateKey, process.env.JWE_SERVER_PUBLICKEY)
      .then((encryptedPayload) => {
        requestPayload = JSON.parse(encryptedPayload)
      });
    }

    try {
      let options = {
        url: endpoint,
        method: httpVerb,
        headers: headers, 
        agentOptions: {
          key: clientPrivateKey,
          cert: clientPublicKey,
        }
     }
     if (sendPayload && payloadEncryption) {
          options.json= requestPayload
      } else if (!payloadEncryption) {
        options.form= requestPayload
      }

      return new Promise((resolve, reject) => {
        request(options, (error, response, body) => {
          if (error) {
            console.log(`Error: ${error}}`)
            reject(error);
          } else {
            console.log(`Response: ${response.statusCode} ${response.statusMessage}`)
            if (payloadEncryption && response.statusCode == success_response_200) {
              securityManager.decryptAndVerifySignPayload(response.body.data, process.env.SUBSCRIPTION_B_APPLICATION, clientPrivateKey, process.env.JWE_SERVER_PUBLICKEY)
                .then((decryptedPayload) => {
                  responsePayload = { code: body.code, message: body.message, data:  decryptedPayload}
                  console.log(responsePayload)
                });
            } else {
              console.log(body)
            }

            // Print relevant headers, for example: Locations contains the resource ID that have been created with POST
            if (response.headers[b_trace_header]) {
              console.log(`Header: [${b_trace_header}=${response.headers[b_trace_header]}]`)
            }
            if(response.statusCode == success_response_201 && response.headers[location_header]){  
              console.log(`Header: [${location_header}=${response.headers[location_header]}]`)
            }
            console.log("---------------------------------------------------------------")

            resolve(response);
          }
        });

      });

    } catch (error) {
      console.error(error);
    }
  }


  /**
   Generates an authorization token using client credentials grant type.
    This method makes a POST request to a specified token URL with the client ID and client secret.
  @function getToken
  @async
  @returns {string} - A promise that resolves with the access token string.
  */
  async getToken() {
    console.log("Generating token ...")
    const HTTP_VERB = "POST"
    const MIME_TYPE = 'application/x-www-form-urlencoded';
    const endpoint = process.env.TOKEN_HOST_DNS + process.env.TOKEN_RESOURCE_NAME
    const payload = {
      grant_type: process.env.TOKEN_GRANT_TYPE,
      client_id: process.env.SUBSCRIPTION_CLIENT_ID,
      client_secret: process.env.SUBSCRIPTION_CLIENT_SECRET,
    }
    const headers = {
      'Content-Type': MIME_TYPE
    }

    let response = await this.doRequest(HTTP_VERB, endpoint, payload, headers, true, false)

    return process.env.TOKEN_AUTH_TYPE + " " + JSON.parse(response.body).access_token
  }

}

const client = new Client();
client.main();