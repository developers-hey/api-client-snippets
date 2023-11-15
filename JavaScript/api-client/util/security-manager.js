/**
 * This Module provides methods signing and encrypting payloads, and decrypting and verifying signed payloads.
 */
const jose = require('jose');
const fs = require('fs');
const rsaPemToJwk = require('rsa-pem-to-jwk');
const p12 = require('p12-pem');


/**
    @constant {string} KEY_ALGORITHM - The algorithm used for RSA keys
    */
const KEY_ALGORITHM = 'RSA'
/**
    @constant {string} JWT_ALGORITHM - The algorithm used for signing JWT
    */
const JWT_ALGORITHM = 'RS256'

/**
    @constant {string} CHARSET_ENCODE - The format for reading PEM files
    */
const CHARSET_ENCODE = 'utf8'
/**
    @constant {string} JWE_ENCRYPTION - The encryption method used for JWE
    */
const JWE_ENCRYPTION = 'A256GCM'

/**
    @constant {string} JWE_ALGORITHM - The JWE algorithm used for encrypting the payload
    */
const JWE_ALGORITHM = 'RSA-OAEP-256'


  /**
   function to get the private key and certificate from the p12 file
  @function getPemFromP12
  @param {string} p12Path - The p12 file path.
  @param {string} p12Passwd - The p12 file password.
  @param {boolean} isPrivateKey - A flag to indicate if is required to get the private or public.
  @returns {string} - A string that cotains the private o public key in pem format.
  */
  function convertP12ToPem(p12Path, p12Passwd, isPrivateKey) {
    let pem = p12.getPemFromP12(p12Path, p12Passwd, CHARSET_ENCODE);

    const PRIVATE_KEY_BEGIN = "-----BEGIN RSA PRIVATE KEY-----"
    const PRIVATE_KEY_END = "-----END RSA PRIVATE KEY-----"
    const PUBLIC_KEY_BEGIN = "-----BEGIN CERTIFICATE-----"
    const PUBLIC_KEY_END = "-----END CERTIFICATE-----"

    if(isPrivateKey) {
      let key = pem.pemKey.replace(PRIVATE_KEY_BEGIN, "").replace(PRIVATE_KEY_END, "");
      key = pemFormatter(key)
      key = `${PRIVATE_KEY_BEGIN}\n${key}${PRIVATE_KEY_END}\n`
      return key;
    } else {
      let certificate = pem.pemCertificate.replace(PUBLIC_KEY_BEGIN, "").replace(PUBLIC_KEY_END, "");
      certificate = pemFormatter(certificate)
      certificate = `${PUBLIC_KEY_BEGIN}\n${certificate}${PUBLIC_KEY_END}\n`
      return certificate;
    }
    
  }


/**
    Signs and encrypts the payload using jose library
    @param {string} payload - The request payload(plain json) to be signed and encrypted
    @param {string} bApplication - The app id of the subscriber in UUID format
    @param {string} clientPrivateKey - The client (API consumer) private key in PEM format
    @param {string} serverPublicKey - The server (API provider) public key in PEM format
    @returns {string} The signed and encrypted payload as a string
    */
    async function signAndEncryptPayload(payload, bApplication, clientPrivateKey, serverPublicKey) {
        console.log("Encrypting and Signing request payload ...")
        const publicKey = await jose.importSPKI(fs.readFileSync(serverPublicKey, CHARSET_ENCODE), KEY_ALGORITHM);

        const jwkPrivateRSA = rsaPemToJwk(clientPrivateKey, { kid: bApplication }, 'private');
        const privateKey = await jose.importJWK(jwkPrivateRSA, JWT_ALGORITHM);
        
        const signedPayload = await new jose.SignJWT(JSON.parse(payload))
            .setProtectedHeader({ alg: JWT_ALGORITHM, kid: bApplication })
            .sign(privateKey);

        const encrypetedPayload = await new jose.CompactEncrypt(new TextEncoder().encode(signedPayload))
            .setProtectedHeader({ alg: JWE_ALGORITHM, enc: JWE_ENCRYPTION, kid: bApplication })
            .encrypt(publicKey)

        return `{"data": "${encrypetedPayload}"}`
    }

/**

   Decrypts and verifies the signature of a JWE/JWS payload.
    @param {string} responsePayload - The response payload(encrypted) to be verified and decrypted
    @param {string} bApplication - The app id of the subscriber in UUID format
    @param {string} clientPrivateKey - The client (API consumer) private key in PEM format
    @param {string} serverPublicKey - The server (API provider) public key in PEM format
    @returns {string} the decrypted and verified payload 
    */
    async function decryptAndVerifySignPayload(responsePayload, bApplication, clientPrivateKey, serverPublicKey) {
        console.log("Decrypting and Verifying signature request payload ...")
        clientPrivateKey = rsaPemToJwk(clientPrivateKey, { kid: bApplication }, 'private');

        clientPrivateKey = await jose.importJWK(clientPrivateKey, JWT_ALGORITHM);

        serverPublicKey = fs.readFileSync(serverPublicKey, CHARSET_ENCODE);
        serverPublicKey = await jose.importSPKI(serverPublicKey, KEY_ALGORITHM);

        const { plaintext } = await jose.compactDecrypt(responsePayload, clientPrivateKey);

        const { payload } = await jose.compactVerify(plaintext, serverPublicKey);
        return new TextDecoder().decode(payload);
    }

    function pemFormatter(text) {
        var result = "";
        while (text.length > 0) {
        result += text.substring(0, 65) + '\n';
        text = text.substring(65);
        }
        return result;
    }


module.exports =
{
    convertP12ToPem,
    signAndEncryptPayload,
    decryptAndVerifySignPayload
}
