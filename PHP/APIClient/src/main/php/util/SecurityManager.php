<?php

/**
 * This Module provides methods for signing and encrypting payloads, and decrypting and verifying signed payloads.
 * @package APIClient\Util
 */

namespace APIClient\Util;

use Exception;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\CompactSerializer as JWSCompactSerializer;
use Jose\Component\KeyManagement\JWKFactory;

/**
 * @constant string KEY_ALGORITHM The algorithm used for RSA keys
 */
const KEY_ALGORITHM = 'RSA';

/**
 * @constant string JWT_ALGORITHM The algorithm used for signing JWT
 */
const JWT_ALGORITHM = 'RS256';

/**
 * @constant string CHARSET_ENCODE The format for reading PEM files
 */
const CHARSET_ENCODE = 'utf8';

/**
 * @constant string JWE_ENCRYPTION The encryption method used for JWE
 */
const JWE_ENCRYPTION = 'A256GCM';

/**
 * @constant string JWE_ALGORITHM The JWE algorithm used for encrypting the payload
 */
const JWE_ALGORITHM = 'RSA-OAEP-256';

class SecurityManager
{
    private $config;
    private $pemPrivateKey;
    private $pemServerPublicKey;

    public function __construct()
    {
        $this->configureOpenSSL();
        $this->config = require __DIR__ . '/../config/config.php';
        $this->validateConfig();
        $this->loadKeys();
    }

    /**
     * Validate configuration keys
     */
    private function validateConfig()
    {
        $requiredKeys = ['MTLS_KEYSTORE_PATH', 'MTLS_KEYSTORE_PASSWD', 'JWE_SERVER_PUBLICKEY'];
        
        foreach ($requiredKeys as $key) {
            if (empty($this->config[$key])) {
                throw new Exception("Missing configuration key: '$key'");
            }
        }
    }

    /**
     * Load private key from PKCS#12 file and server public key
     */
    private function loadKeys()
    {
        $pkcs12File = $this->config['MTLS_KEYSTORE_PATH'];
        $pkcs12Password = $this->config['MTLS_KEYSTORE_PASSWD'];

        if (!file_exists($pkcs12File)) {
            throw new Exception("PKCS#12 file not found: $pkcs12File");
        }

        try {
            $this->loadKeysUsingOpenSSLCommand($pkcs12File, $pkcs12Password);
        } catch (Exception $e) {
            $this->loadKeysUsingPHP($pkcs12File, $pkcs12Password);
        }

        $serverPublicKeyFile = $this->config['JWE_SERVER_PUBLICKEY'];
        if (!file_exists($serverPublicKeyFile)) {
            throw new Exception("Server public key file not found: $serverPublicKeyFile");
        }

        $this->pemServerPublicKey = file_get_contents($serverPublicKeyFile);
        if ($this->pemServerPublicKey === false) {
            throw new Exception("Failed to read server public key file: $serverPublicKeyFile");
        }
    }

    /**
     * Load keys using openssl command (for macOS/OpenSSL 3.0+)
     */
    private function loadKeysUsingOpenSSLCommand($pkcs12File, $pkcs12Password)
    {
        $tempKeyFile = tempnam(sys_get_temp_dir(), 'client_key_');
        
        $command = sprintf(
            'openssl pkcs12 -in %s -out %s -nocerts -nodes -passin pass:%s -provider legacy -provider default 2>/dev/null',
            escapeshellarg($pkcs12File),
            escapeshellarg($tempKeyFile),
            escapeshellarg($pkcs12Password)
        );
        
        $output = [];
        $returnCode = 0;
        exec($command, $output, $returnCode);
        
        if ($returnCode !== 0) {
            @unlink($tempKeyFile);
            throw new Exception("Failed to extract private key using openssl command");
        }
        
        $rawKey = file_get_contents($tempKeyFile);
        @unlink($tempKeyFile);
        
        if (empty($rawKey)) {
            throw new Exception("Extracted private key is empty");
        }
        
        $this->pemPrivateKey = $this->cleanPemKey($rawKey);
    }
    
    /**
     * Clean PEM key to remove additional metadata
     */
    private function cleanPemKey($rawKey)
    {
        $startPattern = '/-----BEGIN [A-Z\s]+KEY-----/';
        $endPattern = '/-----END [A-Z\s]+KEY-----/';
        
        preg_match($startPattern, $rawKey, $startMatches, PREG_OFFSET_CAPTURE);
        preg_match($endPattern, $rawKey, $endMatches, PREG_OFFSET_CAPTURE);
        
        if (empty($startMatches) || empty($endMatches)) {
            throw new Exception("Could not find valid PEM key boundaries");
        }
        
        $startPos = $startMatches[0][1];
        $endPos = $endMatches[0][1] + strlen($endMatches[0][0]);
        
        $cleanKey = substr($rawKey, $startPos, $endPos - $startPos);
        
        if (empty($cleanKey)) {
            throw new Exception("Cleaned PEM key is empty");
        }
        
        return $cleanKey;
    }

    /**
     * Load keys using PHP openssl_pkcs12_read function (fallback)
     */
    private function loadKeysUsingPHP($pkcs12File, $pkcs12Password)
    {
        $pkcs12Content = file_get_contents($pkcs12File);

        if ($pkcs12Content === false) {
            throw new Exception("Failed to read PKCS#12 file: $pkcs12File");
        }

        $certs = [];
        $result = openssl_pkcs12_read($pkcs12Content, $certs, $pkcs12Password);

        if (!$result) {
            $error = "Failed to parse PKCS#12 file. Check the password.";
            $errorDetails = openssl_error_string();
            if ($errorDetails) {
                $error .= " OpenSSL Error: $errorDetails";
            }
            throw new Exception($error);
        }

        if (empty($certs['pkey']) || empty($certs['cert'])) {
            throw new Exception("PKCS#12 file does not contain a private key or certificate.");
        }

        $this->pemPrivateKey = $certs['pkey'];
    }

    /**
     * Decrypt and verify the signature of a JWE/JWS payload.
     * @param string $responsePayload The response payload(encrypted) to be verified and decrypted
     * @return string The decrypted and verified payload
     */
    public function decryptAndVerifySignPayload($responsePayload) 
    {
        echo "Decrypting and Verifying signature request payload ..." . PHP_EOL;
        
        try {
            $jwkPrivate = JWKFactory::createFromKey($this->pemPrivateKey);
            
            $jwkPublic = JWKFactory::createFromKey($this->pemServerPublicKey);
            
            $jweSerializerManager = new JWESerializerManager([
                new JWECompactSerializer()
            ]);
            $jwe = $jweSerializerManager->unserialize($responsePayload);
            
            $encAlg = $jwe->getSharedProtectedHeaderParameter('enc');
            $keyAlg = $jwe->getSharedProtectedHeaderParameter('alg');
            
            if ($keyAlg !== JWE_ALGORITHM) {
                throw new Exception("Unsupported key encryption algorithm: " . $keyAlg);
            }
            
            if ($encAlg !== JWE_ENCRYPTION) {
                throw new Exception("Unsupported content encryption algorithm: " . $encAlg);
            }
            
            $encryptionAlgorithmManager = new AlgorithmManager([
                new RSAOAEP256(),
                new A256GCM()
            ]);
            
            $jweDecrypter = new JWEDecrypter($encryptionAlgorithmManager, null, null);
            
            $success = $jweDecrypter->decryptUsingKey($jwe, $jwkPrivate, 0);
            
            if (!$success) {
                throw new Exception("JWE decryption failed");
            }
            
            $decryptedPayload = $jwe->getPayload();
            
            $jwsSerializerManager = new JWSSerializerManager([
                new JWSCompactSerializer()
            ]);
            $jws = $jwsSerializerManager->unserialize($decryptedPayload);
            
            $signatureAlgorithmManager = new AlgorithmManager([
                new RS256()
            ]);
            
            $jwsVerifier = new JWSVerifier($signatureAlgorithmManager);
            
            $success = $jwsVerifier->verifyWithKey($jws, $jwkPublic, 0);
            
            if (!$success) {
                throw new Exception("JWS verification failed");
            }
            
            return $jws->getPayload();
            
        } catch (Exception $e) {
            throw new Exception("Error decrypting or verifying payload: " . $e->getMessage());
        }
    }

    /**
     * Sign and encrypt payload using JWS + JWE (inverse of decryptAndVerifySignPayload)
     * @param string $payload The JSON payload to sign and encrypt
     * @param string $bApplication The B-Application ID
     * @return string The signed and encrypted payload in format {"data": "encrypted_payload"}
     */
    public function signAndEncryptPayload($payload, $bApplication)
    {
        try {
            echo "Encrypting and Signing request payload ..." . PHP_EOL;
            
            $jwkPrivate = JWKFactory::createFromKey($this->pemPrivateKey);
            $jwkPublic = JWKFactory::createFromKeyFile($this->config['JWE_SERVER_PUBLICKEY']);
            
            $signatureAlgorithmManager = new \Jose\Component\Core\AlgorithmManager([
                new \Jose\Component\Signature\Algorithm\RS256()
            ]);
            
            $jwsBuilder = new \Jose\Component\Signature\JWSBuilder($signatureAlgorithmManager);
            
            $jws = $jwsBuilder
                ->create()
                ->withPayload($payload)
                ->addSignature($jwkPrivate, [
                    'alg' => 'RS256',
                    'kid' => $bApplication
                ])
                ->build();

            $jwsSerializer = new \Jose\Component\Signature\Serializer\CompactSerializer();
            $signedPayload = $jwsSerializer->serialize($jws, 0);

            $keyEncryptionAlgorithm = new \Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256();
            $contentEncryptionAlgorithm = new \Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM();
            
            $encryptionAlgorithmManager = new \Jose\Component\Core\AlgorithmManager([
                $keyEncryptionAlgorithm,
                $contentEncryptionAlgorithm
            ]);

            $jweBuilder = new \Jose\Component\Encryption\JWEBuilder($encryptionAlgorithmManager, $encryptionAlgorithmManager);

            $jwe = $jweBuilder
                ->create()
                ->withPayload($signedPayload)
                ->withSharedProtectedHeader([
                    'alg' => 'RSA-OAEP-256', 
                    'enc' => 'A256GCM',
                    'kid' => $bApplication
                ])
                ->addRecipient($jwkPublic)
                ->build();

            $jweSerializer = new \Jose\Component\Encryption\Serializer\CompactSerializer();
            $encryptedPayload = $jweSerializer->serialize($jwe, 0);

            return json_encode(['data' => $encryptedPayload]);

        } catch (Exception $e) {
            throw new Exception("Error signing and encrypting payload: " . $e->getMessage());
        }
    }

    /**
     * Configure OpenSSL for PKCS#12 compatibility in OpenSSL 3.0+
     */
    private function configureOpenSSL()
    {
        if (defined('OPENSSL_VERSION_TEXT') && (str_contains(OPENSSL_VERSION_TEXT, 'OpenSSL 3.') || str_contains(OPENSSL_VERSION_TEXT, 'OpenSSL 3'))) {
            $tempOpenSSLConf = tempnam(sys_get_temp_dir(), 'openssl_conf_');
            $opensslConfig = "
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
";
            file_put_contents($tempOpenSSLConf, $opensslConfig);
            putenv("OPENSSL_CONF=$tempOpenSSLConf");
            
            ini_set('openssl.legacy_enable', '1');
        }
    }
}