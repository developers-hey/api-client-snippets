const express = require('express');
const bodyParser = require('body-parser');
const request = require('request');
const fs = require('fs');
const tls = require('tls');
const crypto = require('crypto');
const https = require('https');
const { promisify } = require('util');
require('dotenv').config();

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));

const readFileAsync = promisify(fs.readFile);


app.get('/', (req, res) => {
  const authOptions = {
    url: process.env.TOKEN_URL,
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
    },
    form: {
        grant_type: 'client_credentials',
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET
    }
  };

  async function getSSLContext() {
    const clientCert = await readFileAsync('resources/Client_KeyStore_test_Lemus.p12');
    const passphrase = 'Masterkey01';
  
    const clientKey = await crypto.createPrivateKey({
      key: clientCert,
      format: 'pkcs12',
      passphrase,
    });
  
    const options = {
      key: clientKey,
      passphrase,
      rejectUnauthorized: true,
    };
  
    return https.createSecureContext(options);
  }
getSSLContext();
  request.post(authOptions, (error, response, body) => {
    if (!error && response.statusCode === 200) {
      const token = body.access_token;

      const apiOptions = {
        url: process.env.API_URL,
        headers: {
          'Authorization': 'Bearer ' + token
        },
        json: true
      };

      request.get(apiOptions, (error, response, body) => {
        res.send(body);
      });
    } else {
      res.send(error);
    }
  });

});



app.listen(3000, () => {
  console.log('Server listening on port 3000');
});
