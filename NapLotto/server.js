// NapLotto — NapCatQQ WebUI credential HMAC key from Math.random() (CWE-330/338)
// Faithful demo harness. All marked [VERBATIM] blocks are copied unchanged from
// NapNeko/NapCatQQ @ main (2026-11-03); the HTTP scaffolding around them only
// exposes the exact same values the real app exposes, for the PoC to collect.
//
// Real-world mapping:
//   - AuthHelper.secretKey         -> packages/napcat-webui-backend/src/helper/SignToken.ts:5
//   - signCredential/checkCredential/validateCredentialWithinOneHour
//                                  -> SignToken.ts (verbatim)
//   - real_echo oracle             -> packages/napcat-onebot/network/http-server.ts:273
//     (OneBot HTTP API: any request WITHOUT an `echo` field gets a response whose
//      echo is Math.random().toString(36).substring(2,15) — one exact V8
//      Math.random() double per request, same process/stream as the WebUI key.)
//   - napcat-webui-backend/index.ts imports NapCatOneBot11Adapter: the WebUI
//     backend and the OneBot HTTP server run in ONE Node process -> one V8
//     xorshift128+ stream serves both.
//
// Demo instrumentation (NOT part of the real app, clearly marked):
//   GET /key     -> reveals the real secretKey (lets the PoC verify recovery)
//   POST /victim -> returns a credential as if sniffed from a victim admin
//                   session issued 2 hours ago (already expired / revoked)
//   POST /check  -> runs the REAL validateCredentialWithinOneHour() on a
//                   submitted credential: 200 accepted / 401 rejected

'use strict';
const http = require('http');
const crypto = require('crypto');

// [VERBATIM] SignToken.ts:5 — the vulnerable key derivation
const secretKey = process.env['NAPCAT_WEBUI_JWT_SECRET_KEY'] || Math.random().toString(36).slice(2);

// [VERBATIM] SignToken.ts — signCredential / checkCredential / generatePasswordHash /
// validateCredentialWithinOneHour / isCredentialRevoked, transcribed exactly
// (class -> plain functions; the in-memory `store` is a minimal stand-in for
// napcat-common's store with the same 3600s expiry semantics).
const MAX_CREDENTIAL_VALID_SECONDS = 3600;

const store = new Map();               // napcat-common store stand-in

function signCredential(hash) {
  const innerJson = {
    CreatedTime: Math.floor(Date.now() / 1000),
    HashEncoded: hash,
  };
  const jsonString = JSON.stringify(innerJson);
  const hmac = crypto.createHmac('sha256', secretKey).update(jsonString, 'utf8').digest('hex');
  return { Data: innerJson, Hmac: hmac };
}

function checkCredential(credentialJson) {
  try {
    const jsonString = JSON.stringify(credentialJson.Data);
    const calculatedHmac = crypto
      .createHmac('sha256', secretKey)
      .update(jsonString, 'utf8')
      .digest('hex');
    return calculatedHmac === credentialJson.Hmac;
  } catch (_error) {
    return false;
  }
}

function generatePasswordHash(password) {
  return crypto.createHash('sha256').update(password + '.napcat').digest().toString('hex');
}

function isCredentialRevoked(credentialJson) {
  const jsonString = JSON.stringify(credentialJson.Data);
  const hmac = crypto.createHmac('sha256', secretKey).update(jsonString, 'utf8').digest('hex');
  return store.has(`revoked:${hmac}`);
}

function revokeCredential(credentialJson) {
  const jsonString = JSON.stringify(credentialJson.Data);
  const hmac = crypto.createHmac('sha256', secretKey).update(jsonString, 'utf8').digest('hex');
  store.set(`revoked:${hmac}`, true, 3600);
}

function validateCredentialWithinOneHour(token, credentialJson) {
  const isValid = checkCredential(credentialJson);
  if (!isValid) return false;
  if (isCredentialRevoked(credentialJson)) return false;
  const currentTimeSeconds = Math.floor(Date.now() / 1000);
  const createdTimeSeconds = Math.floor(Number(credentialJson.Data.CreatedTime));
  const timeDifferenceSeconds = currentTimeSeconds - createdTimeSeconds;
  const isWithinOneHour = timeDifferenceSeconds >= 0 && timeDifferenceSeconds <= MAX_CREDENTIAL_VALID_SECONDS;
  return isWithinOneHour && credentialJson.Data.HashEncoded === generatePasswordHash(token);
}

// The victim admin's WebUI token — unknown to the attacker. The attacker only
// ever sees HashEncoded = SHA256(token + '.napcat') inside a sniffed credential.
const initialToken = 'victim-admin-token-4f3a9c';

// [VERBATIM] http-server.ts:273 — the OneBot echo oracle
//   const real_echo = payload_echo ?? Math.random().toString(36).substring(2, 15);
function onebotEcho() {
  return Math.random().toString(36).substring(2, 15);
}

const PORT = parseInt(process.env.NAPLOTTO_PORT || '19277', 10);
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
  if (req.method === 'GET' && url.pathname === '/echo') {
    // OneBot action handling: no `echo` payload -> server generates one.
    // (Real responses also carry data/status fields; only the echo matters here.)
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', retcode: 0, echo: onebotEcho() }));
    return;
  }
  if (req.method === 'GET' && url.pathname === '/key') {
    // DEMO-ONLY instrumentation: reveal the real key so the PoC can verify.
    res.writeHead(200);
    res.end(secretKey);
    return;
  }
  if (req.method === 'POST' && url.pathname === '/victim') {
    // DEMO-ONLY instrumentation: a credential from a victim admin session
    // issued 2 hours ago (expired, and treated as revoked) — the "sniffed" value.
    const createdTime = Math.floor(Date.now() / 1000) - 7200;
    const innerJson = { CreatedTime: createdTime, HashEncoded: generatePasswordHash(initialToken) };
    const jsonString = JSON.stringify(innerJson);
    const hmac = crypto.createHmac('sha256', secretKey).update(jsonString, 'utf8').digest('hex');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ Data: innerJson, Hmac: hmac }));
    return;
  }
  if (req.method === 'POST' && url.pathname === '/check') {
    // The REAL server-side validation, applied to a submitted credential.
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      try {
        const cred = JSON.parse(body);
        const ok = validateCredentialWithinOneHour(initialToken, cred);
        res.writeHead(ok ? 200 : 401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ accepted: ok }));
      } catch (_e) {
        res.writeHead(400);
        res.end('{"accepted":false}');
      }
    });
    return;
  }
  res.writeHead(404);
  res.end('not found');
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`NapLotto demo server on 127.0.0.1:${PORT}`);
});
