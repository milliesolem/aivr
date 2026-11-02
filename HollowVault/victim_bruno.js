#!/usr/bin/env node
// VICTIM — a Bruno user on a host without an OS keyring (headless/minimal
// Linux, WSL, Docker, CI, ...). Bruno therefore stores every "secret" through
// its aes256 fallback. This script uses Bruno's OWN vendored encryption code
// (encryptString / encryptStringSafe) exactly as its stores do:
//
//   env-secrets.js :  value: encryptStringSafe(valueToString(v.value)).value
//   oauth2.js      :  encryptStringSafe(safeStringifyJSON(credentials)).value
//   ai-keys.js     :  encryptString(apiKey)
//
// It writes the on-disk store file (secrets.json) that lands in Bruno's
// userData dir. The victim NEVER writes the key anywhere — it is derived
// implicitly from the machine-id inside Bruno's code.
const fs = require('fs');
const path = require('path');
const { encryptString, encryptStringSafe } = require('./vendored/encryption');

// valueToString() from @usebruno/common is identity for string values.
const valueToString = (v) => (typeof v === 'string' ? v : JSON.stringify(v));
const safeStringifyJSON = (o) => JSON.stringify(o);

// ---- The user's REAL secrets entered into Bruno --------------------------
const collectionPath = '/home/victim/work/acme-payments-collection';
const environment = {
  name: 'Production',
  variables: [
    { name: 'authToken', value: 'Bearer EXAMPLE-not-a-real-prod-bearer-7f3b9c2a1d', secret: true },
    { name: 'dbPassword', value: 'EXAMPLE-not-a-real-postgres-password', secret: true },
    { name: 'stripeKey', value: 'EXAMPLE-not-a-real-stripe-live-key-9Hq2', secret: true },
    { name: 'baseUrl', value: 'https://api.acme.example', secret: false } // not secret -> not stored encrypted
  ]
};
const oauth2Credentials = {
  access_token: 'EXAMPLE-not-a-real-google-oauth-access-token',
  refresh_token: 'EXAMPLE-not-a-real-google-oauth-refresh-token',
  token_type: 'Bearer',
  expires_in: 3599
};
const aiProviderApiKey = 'EXAMPLE-not-a-real-anthropic-api-key-0042';

// ---- Encrypt exactly like Bruno's stores do ------------------------------
// env-secrets.js  (EnvironmentSecretsStore.storeEnvSecrets)
const secrets = environment.variables
  .filter((v) => v.secret)
  .map((v) => ({ name: v.name, value: encryptStringSafe(valueToString(v.value)).value }));

// oauth2.js  (Oauth2Store.updateCredentials)
const oauth2Blob = encryptStringSafe(safeStringifyJSON(oauth2Credentials)).value;

// ai-keys.js  (AiKeysStore)
const aiKeyBlob = encryptString(aiProviderApiKey);

// ---- Persist the Bruno "secrets" store file ------------------------------
const store = {
  collections: [{ path: collectionPath, environments: [{ name: environment.name, secrets }] }],
  oauth2: [{ collectionPath, data: oauth2Blob }],
  aiKeys: [{ provider: 'anthropic', key: aiKeyBlob }]
};

const outDir = path.join(__dirname, 'bruno_userdata');
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'secrets.json'), JSON.stringify(store, null, 2));

console.log('== VICTIM: wrote Bruno secrets store (bruno_userdata/secrets.json) ==');
console.log('   Every value is stored "encrypted" with the $01 (aes256) algo:\n');
for (const s of secrets) console.log(`   env secret  ${s.name.padEnd(11)} -> ${s.value}`);
console.log(`   oauth2 creds           -> ${oauth2Blob.slice(0, 72)}...`);
console.log(`   ai provider key        -> ${aiKeyBlob.slice(0, 72)}...`);
console.log('\n   The victim never stored any passphrase/key. Done.');
