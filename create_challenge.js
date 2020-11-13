// Modified from sample code provided by Auth0
// https://auth0.com/docs/flows/call-your-api-using-the-authorization-code-flow-with-pkce#javascript-sample

const crypto = require('crypto');

function base64URLEncode(str) {
    return str.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function sha256(buffer) {
    return crypto.createHash('sha256').update(buffer).digest();
}

function createVerifier() {
    return base64URLEncode(crypto.randomBytes(32));
}

function createChallenge(v){
    return base64URLEncode(sha256(v));
}

var verifier = createVerifier();
var challenge = createChallenge(verifier);

console.log("Verifier: " + verifier);
console.log("Challenge: " + challenge);