// Victim: faithful reproduction of JumpServer apps/static/js/session-encrypt.js
// (rsaEncryptPassword path). Emits what a passive attacker can observe.
const crypto = require('crypto');

function fillKey(key) {
  const keyLength = 16;
  if (key.length > keyLength) key = key.slice(0, keyLength);
  const filledKey = Buffer.alloc(keyLength);
  const keys = Buffer.from(key);
  for (let i = 0; i < keys.length; i++) filledKey[i] = keys[i];
  return filledKey;
}
// CryptoJS.AES ECB + ZeroPadding, 16-byte key  ==  Node aes-128-ecb (zero pad)
function aesEncrypt(text, originKey) {
  const key = fillKey(originKey);
  const c = crypto.createCipheriv('aes-128-ecb', key, null);
  c.setAutoPadding(false);
  const buf = Buffer.from(text, 'utf8');
  const pad = (16 - (buf.length % 16)) % 16;
  const padded = Buffer.concat([buf, Buffer.alloc(pad)]);
  return Buffer.concat([c.update(padded), c.final()]).toString('base64');
}

// JumpServer backend RSA keypair (attacker does NOT have the private key)
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// ---- what the attacker passively observes from the victim's JS realm ----
// Any few Math.random() outputs from the same V8 stream (co-resident script,
// same-origin XSS, or app-leaked random ids/nonces).
const observed = [];
for (let i = 0; i < 5; i++) observed.push(Math.random());

// ---- victim encrypts a privileged credential, exactly as JumpServer does ----
const secret = 'R00t@sset-Vault-PW#2026';         // a privileged asset password
const aesKey = (Math.random() + 1).toString(36).substring(2);   // <-- CWE-338 key
const passwordCipher = aesEncrypt(secret, aesKey);
const keyCipher = crypto.publicEncrypt(
  { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
  Buffer.from(aesKey)
).toString('base64');

// capture.json = attacker's view (+ _debug to verify the break afterwards)
console.log(JSON.stringify({
  observed,
  passwordCipher,          // captured credential ciphertext
  keyCipher,               // RSA(aesKey) — useless without server privkey
  _debug: { secret, aesKey },
}, null, 2));
