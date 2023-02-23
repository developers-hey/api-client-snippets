const https = require('https');

// Paso 1: Obtener el token de autorización
const getToken = () => {
  const options = {
    hostname: 'sbox-tech.hey.inc',
    path: '/api-auth/v1/oidc/token',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  };

  const data = new URLSearchParams({
    'grant_type': 'client_credentials',
    'client_id': 'BRM14393',
    'client_secret': '3c0ba7de-6f12-45fb-bb85-57c8ffc0591b'
  });

  const req = https.request(options, res => {
    let body = '';
    res.on('data', chunk => {
      body += chunk;
    });
    res.on('end', () => {
      const token = JSON.parse(body).access_token;
      // Paso 2: Consumir el endpoint con el token de seguridad obtenido en paso 1
      makeRequest(token);
    });
  });

  req.on('error', error => {
    console.error(error);
  });

  req.write(data.toString());
  req.end();
}

// Paso 2: Consumir el endpoint con el token de seguridad obtenido en paso 1
const makeRequest = token => {
  const options = {
    hostname: 'sbox-tech.hey.inc',
    path: '/api/taas/v1.0/interbank-transfers',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Accept-Charset': 'UTF-8',
      'B-Transaction': '12345',
      'B-application': 'b2aebc2c-13d3-4abc-bb88-c0cef90e8afd',
      'Authorization': `Bearer ${token}`
    }
  };

  const data = JSON.stringify({
    "issuerAccountId": "85b7d49f-2027-4033-a206-4f65fd04bb2c",
    "recipient": {
      "financialEntityId": "106",
      "accountNumber": "123456789765434564",
      "accountTypeId": 3,
      "name": "PoD",
      "lastName": "TGBlIii",
      "secondLastName": "netpop",
      "businessName": "Hey Banco",
      "rfc": "GGSP010112B23",
      "curp": "AASP010821HNLLNDA7",
      "taxRegimeId": "F",
      "riskLevelId": 2
    },
    "amount": 1,
    "concept": "lhkl",
    "numericalReference": "1234567",
    "type": "SPEI"
  });

  const req = https.request(options, res => {
    let body = '';
    res.on('data', chunk => {
      body += chunk;
    });
    res.on('end', () => {
      console.log(body);
    });
  });

  req.on('error', error => {
    console.error(error);
  });

  req.write(data);
  req.end();
}

// Llamada a la función para obtener el token de autorización
getToken();
