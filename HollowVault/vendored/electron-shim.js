// Minimal stand-in for `require('electron')` used ONLY to run Bruno's
// encryption.js off-Electron. It reports that OS-backed secure storage is
// UNAVAILABLE — which is exactly what Electron's safeStorage does on any host
// without a usable OS keyring (headless / minimal Linux, WSL, Docker, CI,
// keyring-less sessions). In that state Bruno's encryptString() takes its
// documented fallback branch: aes256Encrypt(str) keyed by SHA256(machineId).
//
// (When safeStorage IS available, env secrets instead get the '$00:' prefix
//  and are protected by the OS keyring. This PoC targets the '$01:' fallback.)
const safeStorage = {
  isEncryptionAvailable() {
    return false;
  },
  encryptString() {
    throw new Error('safeStorage unavailable');
  },
  decryptString() {
    throw new Error('safeStorage unavailable');
  }
};

module.exports = { safeStorage };
