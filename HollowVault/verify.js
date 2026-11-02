#!/usr/bin/env node
// VERIFY — cross-check the attacker's secret-free recovery against (a) the
// known ground-truth plaintext and (b) Bruno's OWN decryptString() round-trip.
const fs = require('fs');
const path = require('path');
const { encryptString, decryptString } = require('./vendored/encryption');

const recovered = JSON.parse(fs.readFileSync(path.join(__dirname, 'bruno_userdata', 'recovered.json'), 'utf8'));

const groundTruth = {
  'env:Production:authToken': 'Bearer EXAMPLE-not-a-real-prod-bearer-7f3b9c2a1d',
  'env:Production:dbPassword': 'EXAMPLE-not-a-real-postgres-password',
  'env:Production:stripeKey': 'EXAMPLE-not-a-real-stripe-live-key-9Hq2',
  'ai:anthropic': 'EXAMPLE-not-a-real-anthropic-api-key-0042'
};

let pass = 0;
let total = 0;
console.log('== VERIFY: attacker output vs. ground truth ==');
for (const [k, v] of Object.entries(groundTruth)) {
  total++;
  const ok = recovered[k] === v;
  pass += ok ? 1 : 0;
  console.log(`   ${ok ? 'OK ' : 'XX '} ${k} = ${recovered[k]}`);
}
// oauth2 tokens
total += 2;
const oauthOk =
  recovered.oauth2 &&
  recovered.oauth2.access_token === 'EXAMPLE-not-a-real-google-oauth-access-token' &&
  recovered.oauth2.refresh_token === 'EXAMPLE-not-a-real-google-oauth-refresh-token';
pass += oauthOk ? 2 : 0;
console.log(`   ${oauthOk ? 'OK ' : 'XX '} oauth2 access_token + refresh_token recovered`);

// Confirm Bruno's own decryptString round-trips what the attacker produced
const rt = decryptString(encryptString('round-trip-check'));
const rtOk = rt === 'round-trip-check';
console.log(`\n   Bruno decryptString(encryptString(x)) == x ?  ${rtOk}`);

console.log(`\nRESULT: ${pass}/${total} credentials recovered WITHOUT any secret.  ${pass === total && rtOk ? 'PASS' : 'FAIL'}`);
process.exit(pass === total && rtOk ? 0 : 1);
