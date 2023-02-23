const express = require('express');
const bodyParser = require('body-parser');
const request = require('request');
require('dotenv').config();

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));

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
