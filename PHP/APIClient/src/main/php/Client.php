<?php

/**
 * This module exports the Client class, which is used to make HTTP requests
 * to an API using OAuth 2.0 authentication with client credentials grant flow
 * and encrypted payloads.
 * @package APIClient
 */

require_once __DIR__ . '/../../../../vendor/autoload.php';
require_once __DIR__ . '/util/SecurityManager.php';

use APIClient\Util\SecurityManager;

class Client
{
    private $config;
    private $securityManager;

    public function __construct()
    {
        $this->config = require __DIR__ . '/config/config.php';
        
        if (empty($this->config['MTLS_KEYSTORE_PATH']) || empty($this->config['MTLS_KEYSTORE_PASSWD'])) {
            throw new Exception("Missing mTLS configuration in 'config.php'. Please define 'MTLS_KEYSTORE_PATH' and 'MTLS_KEYSTORE_PASSWD'.");
        }
        
        $this->securityManager = new SecurityManager();
    }

    public function main()
    {
        $token = $this->getToken();
        $defaultBankingOption = '0';
        
        $headers = [
            'Authorization: ' . $token,
            'B-Application: ' . $this->config['SUBSCRIPTION_B_APPLICATION'],
            'B-Transaction: ' . $this->config['REQUEST_B_TRANSACTION'],
            'B-Option: ' . $defaultBankingOption,
            'Content-Type: ' . $this->config['REQUEST_MIME_TYPE'],
            'Accept: ' . $this->config['REQUEST_MIME_TYPE'],
            'Accept-Charset: ' . $this->config['REQUEST_ENCODE_CHARSET']
        ];

        if ($this->config['REQUEST_MFA_ACTIVE'] === true) {
            $authenticationCode = $this->getAuthenticationCode($headers);
            $headers[] = 'B-Authentication-Code: ' . $authenticationCode;
        }
        
        foreach ($headers as $headerIndex => $headerString) {
            if (strpos($headerString, 'B-Option:') === 0) {
                $headers[$headerIndex] = 'B-Option: ' . $this->config['REQUEST_B_OPTION'];
                break;
            }
        }
        
        $apiEndpoint = $this->config['API_HOST_DNS'] . $this->config['API_BASE_PATH'] . $this->config['API_RESOURCE_NAME'];
        $this->doRequest(
            $this->config['REQUEST_HTTP_VERB'], 
            $apiEndpoint, 
            $this->config['REQUEST_UNENCRYPTED_PAYLOAD'], 
            $headers, 
            $this->config['REQUEST_SEND_PAYLOAD'], 
            true
        );
    }

    /**
     * Makes a request to the API using the provided parameters and the access token.
     * @param string $httpVerb The HTTP method for the API request.
     * @param string $endpoint The endpoint for the API request.
     * @param string|null $requestPayload The request body for the API request, if any.
     * @param array $headers The headers for the API request.
     * @param bool $sendPayload Flag to indicate if the request must include the body.
     * @param bool $payloadEncryption Flag to indicate if encryption is required for the request payload.
     * @return void
     */
    public function doRequest($httpVerb, $endpoint, $requestPayload, $headers, $sendPayload, $payloadEncryption)
    {
        echo "===============================================================" . PHP_EOL;
        echo "Request $httpVerb: $endpoint" . PHP_EOL;
        
        $successResponse200 = 200;
        $successResponse201 = 201;
        $httpVerbGet = "GET";
        $bTraceHeader = "b-trace";
        $locationHeader = "location";

        $curlHandle = curl_init();
        curl_setopt($curlHandle, CURLOPT_URL, $endpoint);
        curl_setopt($curlHandle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curlHandle, CURLOPT_HEADER, true);
        curl_setopt($curlHandle, CURLOPT_HTTPHEADER, $headers);
        
        $httpVerbUpper = strtoupper($httpVerb);
        if ($httpVerbUpper === 'POST') {
            curl_setopt($curlHandle, CURLOPT_POST, true);
        } elseif ($httpVerbUpper === 'PUT') {
            curl_setopt($curlHandle, CURLOPT_CUSTOMREQUEST, 'PUT');
        } elseif ($httpVerbUpper === 'PATCH') {
            curl_setopt($curlHandle, CURLOPT_CUSTOMREQUEST, 'PATCH');
        } elseif ($httpVerbUpper === 'DELETE') {
            curl_setopt($curlHandle, CURLOPT_CUSTOMREQUEST, 'DELETE');
        }
        
        if ($sendPayload && $payloadEncryption && !empty($requestPayload)) {
            $encryptedPayload = $this->securityManager->signAndEncryptPayload(
                $requestPayload, 
                $this->config['SUBSCRIPTION_B_APPLICATION']
            );
            curl_setopt($curlHandle, CURLOPT_POSTFIELDS, $encryptedPayload);
        }
        
        $requestHeadersArray = [];
        foreach ($headers as $headerString) {
            $headerParts = explode(': ', $headerString, 2);
            if (count($headerParts) === 2) {
                $requestHeadersArray[$headerParts[0]] = $headerParts[1];
            }
        }
        echo "Headers: [" . json_encode($requestHeadersArray) . "]" . PHP_EOL;
        
        curl_setopt($curlHandle, CURLOPT_SSLCERT, $this->config['MTLS_KEYSTORE_PATH']);
        curl_setopt($curlHandle, CURLOPT_SSLCERTPASSWD, $this->config['MTLS_KEYSTORE_PASSWD']);
        curl_setopt($curlHandle, CURLOPT_SSLCERTTYPE, 'P12');
        
        curl_setopt($curlHandle, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($curlHandle, CURLOPT_SSL_VERIFYHOST, 2);

        $responseWithHeaders = curl_exec($curlHandle);

        if (curl_errno($curlHandle)) {
            echo "cURL Error: " . curl_error($curlHandle) . PHP_EOL;
            curl_close($curlHandle);
            return;
        }

        $httpCode = curl_getinfo($curlHandle, CURLINFO_HTTP_CODE);
        $responseHeaderSize = curl_getinfo($curlHandle, CURLINFO_HEADER_SIZE);
        echo "Response: $httpCode" . PHP_EOL;

        $responseHeaders = [];
        $response = $responseWithHeaders;
        
        if ($responseHeaderSize > 0) {
            $responseHeaderText = substr($responseWithHeaders, 0, $responseHeaderSize);
            $response = substr($responseWithHeaders, $responseHeaderSize);
            
            $responseHeaderLines = explode("\r\n", $responseHeaderText);
            foreach ($responseHeaderLines as $headerLine) {
                if (strpos($headerLine, ':') !== false) {
                    list($headerName, $headerValue) = explode(':', $headerLine, 2);
                    $responseHeaders[strtolower(trim($headerName))] = trim($headerValue);
                }
            }
        }

        curl_close($curlHandle);

        $responsePayload = json_decode($response, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Failed to decode JSON response: " . json_last_error_msg());
        }

        if ($payloadEncryption && $httpCode == $successResponse200 && strtoupper($httpVerb) == $httpVerbGet) {
            if (isset($responsePayload['data'])) {
                try {
                    $decryptedData = $this->securityManager->decryptAndVerifySignPayload($responsePayload['data']);
                    
                    $finalResponse = [
                        'code' => $responsePayload['code'],
                        'message' => $responsePayload['message'],
                        'data' => json_decode($decryptedData, true)
                    ];
                    
                    if (isset($responsePayload['metadata'])) {
                        $finalResponse['metadata'] = $responsePayload['metadata'];
                    }
                    
                    echo json_encode($finalResponse, JSON_PRETTY_PRINT) . PHP_EOL;
                } catch (Exception $exception) {
                    echo "Error decrypting or verifying payload: " . $exception->getMessage() . PHP_EOL;
                }
            } else {
                echo json_encode($responsePayload, JSON_PRETTY_PRINT) . PHP_EOL;
            }
        } else {
            echo json_encode($responsePayload, JSON_PRETTY_PRINT) . PHP_EOL;
        }
        
        if (isset($responseHeaders[$bTraceHeader])) {
            echo "Header: [$bTraceHeader=" . $responseHeaders[$bTraceHeader] . "]" . PHP_EOL;
        }
        if ($httpCode == $successResponse201 && isset($responseHeaders[$locationHeader])) {
            echo "Header: [$locationHeader=" . $responseHeaders[$locationHeader] . "]" . PHP_EOL;
        }
        
        echo "---------------------------------------------------------------" . PHP_EOL;
    }

    /**
     * Generates an authorization token using client credentials grant type.
     * This method makes a POST request to a specified token URL with the client ID and client secret.
     * @return string The access token string.
     */
    private function getToken()
    {
        echo "Generating token ..." . PHP_EOL;
        
        $httpVerb = "POST";
        $requestContentType = 'application/x-www-form-urlencoded';
        $endpoint = $this->config['TOKEN_HOST_DNS'] . $this->config['TOKEN_RESOURCE_NAME'];
        
        $tokenRequestPayload = http_build_query([
            'grant_type' => $this->config['TOKEN_GRANT_TYPE'],
            'client_id' => $this->config['SUBSCRIPTION_CLIENT_ID'],
            'client_secret' => $this->config['SUBSCRIPTION_CLIENT_SECRET'],
            'scope' => $this->config['TOKEN_SCOPE'],
        ]);

        $headers = [
            "Content-Type: $requestContentType",
            "Accept: application/json",
            "User-Agent: PHP-Client/1.0",
            "Cache-Control: no-cache",
            "Connection: keep-alive",
        ];

        echo "===============================================================" . PHP_EOL;
        echo "Request $httpVerb: $endpoint" . PHP_EOL;
        
        $requestHeadersArray = [];
        foreach ($headers as $headerString) {
            $headerParts = explode(': ', $headerString, 2);
            if (count($headerParts) === 2) {
                $requestHeadersArray[$headerParts[0]] = $headerParts[1];
            }
        }
        echo "Headers: [" . json_encode($requestHeadersArray) . "]" . PHP_EOL;

        $curlHandle = curl_init();
        curl_setopt($curlHandle, CURLOPT_URL, $endpoint);
        curl_setopt($curlHandle, CURLOPT_POST, true);
        curl_setopt($curlHandle, CURLOPT_POSTFIELDS, $tokenRequestPayload);
        curl_setopt($curlHandle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curlHandle, CURLOPT_HTTPHEADER, $headers);
        
        curl_setopt($curlHandle, CURLOPT_SSLCERT, $this->config['MTLS_KEYSTORE_PATH']);
        curl_setopt($curlHandle, CURLOPT_SSLCERTPASSWD, $this->config['MTLS_KEYSTORE_PASSWD']);
        curl_setopt($curlHandle, CURLOPT_SSLCERTTYPE, 'P12');
        
        curl_setopt($curlHandle, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($curlHandle, CURLOPT_SSL_VERIFYHOST, 2);

        $response = curl_exec($curlHandle);

        if (curl_errno($curlHandle)) {
            throw new Exception("cURL Error: " . curl_error($curlHandle));
        }

        $httpCode = curl_getinfo($curlHandle, CURLINFO_HTTP_CODE);
        curl_close($curlHandle);

        echo "Response: $httpCode" . PHP_EOL;
        echo "---------------------------------------------------------------" . PHP_EOL;

        if ($httpCode !== 200) {
            throw new Exception("Failed to fetch token from $endpoint. HTTP Code: $httpCode. Response: $response");
        }

        $responsePayload = json_decode($response, true);

        if (!isset($responsePayload['access_token'])) {
            throw new Exception("Invalid token response: " . $response);
        }

        return $this->config['TOKEN_AUTH_TYPE'] . ' ' . $responsePayload['access_token'];
    }

    /**
     * Generates an OTP MFA code.
     * This method makes a GET request to a specified endpoint to get the OTP MFA code.
     * @param array $headers Headers for the API request
     * @return string The OTP MFA code string
     */
    private function getAuthenticationCode($headers)
    {
        echo "Generating OTP MFA ..." . PHP_EOL;
        
        $httpVerb = "GET";
        $endpoint = $this->config['TOKEN_HOST_DNS'] . $this->config['API_RESOURCE_NAME_VERIFICATION_CODE'];
        
        echo "===============================================================" . PHP_EOL;
        echo "Request $httpVerb: $endpoint" . PHP_EOL;
        
        $requestHeadersArray = [];
        foreach ($headers as $headerString) {
            $headerParts = explode(': ', $headerString, 2);
            if (count($headerParts) === 2) {
                $requestHeadersArray[$headerParts[0]] = $headerParts[1];
            }
        }
        echo "Headers: [" . json_encode($requestHeadersArray) . "]" . PHP_EOL;

        $curlHandle = curl_init();
        curl_setopt($curlHandle, CURLOPT_URL, $endpoint);
        curl_setopt($curlHandle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curlHandle, CURLOPT_HTTPHEADER, $headers);
        
        curl_setopt($curlHandle, CURLOPT_SSLCERT, $this->config['MTLS_KEYSTORE_PATH']);
        curl_setopt($curlHandle, CURLOPT_SSLCERTPASSWD, $this->config['MTLS_KEYSTORE_PASSWD']);
        curl_setopt($curlHandle, CURLOPT_SSLCERTTYPE, 'P12');
        
        curl_setopt($curlHandle, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($curlHandle, CURLOPT_SSL_VERIFYHOST, 2);

        $response = curl_exec($curlHandle);

        if (curl_errno($curlHandle)) {
            throw new Exception("cURL Error: " . curl_error($curlHandle));
        }

        $httpCode = curl_getinfo($curlHandle, CURLINFO_HTTP_CODE);
        curl_close($curlHandle);

        echo "Response: $httpCode" . PHP_EOL;
        echo "---------------------------------------------------------------" . PHP_EOL;

        if ($httpCode !== 200) {
            throw new Exception("Failed to fetch authentication code from $endpoint. HTTP Code: $httpCode. Response: $response");
        }

        $responsePayload = json_decode($response, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Failed to decode JSON response: " . json_last_error_msg());
        }

        if (isset($responsePayload['data'])) {
            try {
                $decryptedData = $this->securityManager->decryptAndVerifySignPayload($responsePayload['data']);
                $decryptedAuthPayload = json_decode($decryptedData, true);
                
                if (isset($decryptedAuthPayload['authentication-code'])) {
                    return $decryptedAuthPayload['authentication-code'];
                } else {
                    throw new Exception("Authentication code not found in decrypted payload");
                }
            } catch (Exception $exception) {
                throw new Exception("Error decrypting authentication code payload: " . $exception->getMessage());
            }
        } else {
            throw new Exception("No data field found in authentication code response");
        }
    }
}

/**
 * Helper function to convert string to boolean like JavaScript
 */
function getEnvAsBoolean($envVariable) {
    return $envVariable === 'true';
}

$client = new Client();
$client->main();

