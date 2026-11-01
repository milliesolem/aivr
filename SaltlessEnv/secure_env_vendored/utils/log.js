'use strict'
// Minimal stand-in for secure-env's internal logger so the *verbatim* upstream
// cryptography.js (copied unmodified from secure-env@1.2.0) can run offline.
// The real logger only prints coloured status lines; behaviour is irrelevant to the PoC.
module.exports = function log (message, level) {
  const tag = level ? `[secure-env:${level}]` : '[secure-env]'
  if (level === 'error') console.error(tag, message)
  // info/warn chatter is silenced to keep PoC output clean
}
