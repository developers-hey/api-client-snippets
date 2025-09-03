<?php

return [
    // Subscription Configuration
    'SUBSCRIPTION_B_APPLICATION' => '4fd8cd19-a24a-5621-8c0f-6943217d4f28',
    'SUBSCRIPTION_CLIENT_ID' => '1a6e1b8c-eada-4082-a4b9-1dbb208ba689',
    'SUBSCRIPTION_CLIENT_SECRET' => 'vgPxpZvSZLeUGivw7lK0Ddf6u',

    // API Configuration
    'API_HOST_DNS' => 'https://sbox-api-tech.hey.inc',
    'API_BASE_PATH' => '/misc/v1.0',
    'API_RESOURCE_NAME' => '/webhooks',
    'API_RESOURCE_NAME_VERIFICATION_CODE' => '/misc/v1.0/verification-codes',

    // Token Configuration
    'TOKEN_HOST_DNS' => 'https://sbox-api-tech.hey.inc',
    'TOKEN_RESOURCE_NAME' => '/auth/v1/oidc/token',
    'TOKEN_GRANT_TYPE' => 'client_credentials',
    'TOKEN_AUTH_TYPE' => 'Bearer',
    'TOKEN_SCOPE' => 'openid',

    // mTLS Configuration
    'MTLS_KEYSTORE_PATH' => '/home/API/Client_KeyStore_mTLS.p12',
    'MTLS_KEYSTORE_PASSWD' => 's+ebd7DbKOqv2zCfJtTl9SnN/wbBTiWu8E=',

    // JWE Configuration
    'JWE_SERVER_PUBLICKEY' => '/home/API/Server_PublicKey_JWE.pem',

    // Request Configuration
    'REQUEST_HTTP_VERB' => 'GET',
    'REQUEST_SEND_PAYLOAD' => false,
    'REQUEST_UNENCRYPTED_PAYLOAD' => 'REQUEST_UNENCRYPTED_PAYLOAD= {"clientId": "Snippet-test", "clientSecret": "11598ae8-1170-a058-92ff-a1afc4b12c44", "authenticationUrl": "https://fintech.com/base/callback-api/v1.0/authentication", "notificationUrl": "https://fintech.com/base/callback-api/v1.0/notifications", "authorizationUrl": "https://fintech.com/base/callback-api/v1.0/authorization", "events": [{"id": 1 }]}',
    'REQUEST_B_TRANSACTION' => '12345678',
    'REQUEST_B_OPTION' => 0,
    'REQUEST_MIME_TYPE' => 'application/json',
    'REQUEST_ENCODE_CHARSET' => 'UTF-8',
    'REQUEST_MFA_ACTIVE' => false,
];
