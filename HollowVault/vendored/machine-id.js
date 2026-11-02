// ===========================================================================
// Faithful port of @usebruno/node-machine-id v2.0.0 (index.js), the exact
// package Bruno depends on (packages/bruno-electron/package.json:
// "@usebruno/node-machine-id": "^2.0.0").
// Source: https://unpkg.com/@usebruno/node-machine-id@2.0.0/index.js
//
// The ONLY change: `require('native-reg')` is made LAZY (moved inside the
// win32-only branch) so this runs on Linux/macOS without the native module.
// The Linux/macOS/freebsd code path is byte-identical to upstream.
//
// Key facts this encodes (used by the finding):
//   * machineIdSync()            -> sha256( rawId )           (hex string)
//   * machineIdSync(true)        -> rawId  (the raw, NON-secret identifier)
//   * rawId (linux) = `cat /var/lib/dbus/machine-id /etc/machine-id` and, if
//     BOTH are missing, falls back to `hostname`.  All world-readable.
// ===========================================================================
const { exec, execSync } = require('child_process');
const { createHash } = require('crypto');

let { platform } = process;

let win32RegBinPath = {
  native: '%windir%\\System32',
  mixed: '%windir%\\sysnative\\cmd.exe /c %windir%\\System32'
};
let guid = {
  darwin: 'ioreg -rd1 -c IOPlatformExpertDevice',
  win32:
    `${win32RegBinPath[isWindowsProcessMixedOrNativeArchitecture()]}\\REG.exe ` +
    'QUERY HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography ' +
    '/v MachineGuid',
  linux: '( cat /var/lib/dbus/machine-id /etc/machine-id 2> /dev/null || hostname ) | head -n 1 || :',
  freebsd: 'kenv -q smbios.system.uuid || sysctl -n kern.hostuuid'
};

function isWindowsProcessMixedOrNativeArchitecture() {
  if (process.platform !== 'win32') {
    return '';
  }
  if (process.arch === 'ia32' && process.env.hasOwnProperty('PROCESSOR_ARCHITEW6432')) {
    return 'mixed';
  }
  return 'native';
}

function hash(guid) {
  return createHash('sha256').update(guid).digest('hex');
}

function expose(result) {
  switch (platform) {
    case 'darwin':
      return result.split('IOPlatformUUID')[1].split('\n')[0].replace(/\=|\s+|\"/gi, '').toLowerCase();
    case 'win32':
      return result.toString().split('REG_SZ')[1].replace(/\r+|\n+|\s+/gi, '').toLowerCase();
    case 'linux':
      return result.toString().replace(/\r+|\n+|\s+/gi, '').toLowerCase();
    case 'freebsd':
      return result.toString().replace(/\r+|\n+|\s+/gi, '').toLowerCase();
    default:
      throw new Error(`Unsupported platform: ${process.platform}`);
  }
}

function getWindowsMachineId() {
  const reg = require('native-reg'); // lazy (win32-only) — see header note
  return reg.getValue(reg.HKEY.LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Cryptography', 'MachineGuid').toString();
}

function machineIdSync(original) {
  let error;
  try {
    let id = expose(execSync(guid[platform]).toString());
    return original ? id : hash(id);
  } catch (e) {
    error = e;
  }
  if (platform === 'win32') {
    try {
      let id = getWindowsMachineId();
      return original ? id : hash(id);
    } catch (e) {
      throw new Error(`Error while obtaining machine id via native-reg: ${e.stack}`);
    }
  }
  if (error) {
    throw new Error(`Error while obtaining machine id: ${error.stack}`);
  }
}

module.exports = { machineIdSync, machineId: machineIdSync };
