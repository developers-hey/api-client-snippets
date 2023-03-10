/**
 * This Module provides methods signing and encrypting payloads, and decrypting and verifying signed payloads.
 */
const jose = require('jose');
const fs = require('fs');
const rsaPemToJwk = require('rsa-pem-to-jwk');
const dotenv = require('dotenv');

dotenv.config();

/**
    @constant {string} algorithm - The algorithm used for RSA keys
    */
const algorithm = 'RSA'
/**
    @constant {string} alg - The algorithm used for signing JWT
    */
const alg = 'RS256'

/**
    @constant {string} format - The format for reading PEM files
    */
const format = 'utf8'
/**
    @constant {string} EncryptionMethod - The encryption method used for JWE
    */
const EncryptionMethod = 'A256GCM'

/**
    @constant {string} JWEAlgorithm - The JWE algorithm used for encrypting the payload
    */
const JWEAlgorithm = 'RSA-OAEP-256'


/**

    Signs and encrypts the payload using jose library
    @param {string} requestPayload - The payload to be signed and encrypted
    @returns {string} The signed and encrypted payload as a string
    */
async function signAndEncryptPayload(requestPayload) {
    loadKeys();
    publicKey = await jose.importSPKI(publicPem, algorithm);
    privateKey = await jose.importJWK(jwkPrivateRSA, alg);

    const jsonPayload = JSON.parse(requestPayload);
    const strSigned = await new jose.SignJWT(jsonPayload)
        .setProtectedHeader({ alg })
        .sign(privateKey);

    const strEncrypt = await new jose.CompactEncrypt(
        new TextEncoder().encode(strSigned),
    )
        .setProtectedHeader({ alg: JWEAlgorithm, enc: EncryptionMethod, kid: process.env.B_APPLICATION })
        .encrypt(publicKey)
    return strEncrypt
}

/**

   Decrypts and verifies the signature of a JWE/JWS payload.
    @param {string} requestPayload - the JWE/JWS payload to be decrypted and verified
    @returns {string} the decrypted and verified payload 
    */

async function decryptAndVerifySignPayload(responsePayload) {
    loadKeys();
    publicKey = await jose.importSPKI(publicPem, algorithm);
    privateKey = await jose.importJWK(jwkPrivateRSA, alg);
    const { plaintext } = await jose.compactDecrypt(responsePayload, privateKey);
    const strDecrypt = new TextDecoder().decode(plaintext);
    const { payload } = await jose.compactVerify(strDecrypt, publicKey);
    return new TextDecoder().decode(payload);
}

/**
     Parses the private and public keys in PEM format and sets them as JWK objects.
    
*/
function loadKeys() {
    privatePem = fs.readFileSync(process.env.PRIVATE_KEY_PATH, format);
    jwkPrivateRSA = rsaPemToJwk(privatePem, { kid: process.env.B_APPLICATION }, 'private');
    publicPem = fs.readFileSync(process.env.PUBLIC_KEY_PATH, format);
}
module.exports =
{
    signAndEncryptPayload,
    decryptAndVerifySignPayload
}
