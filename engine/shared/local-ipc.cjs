const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

async function createPrivateTempDirectory(prefix = 'ns2-') {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  // POSIX mode bits do not provide the same security model on Windows.
  // Keep the upstream permissions on Unix and rely on the current user's
  // Windows temp directory ACL there.
  if (process.platform !== 'win32') await fs.chmod(directory, 0o700);
  return directory;
}

function localIpcPath(directory, name = 'memory', options = {}) {
  const platform = options.platform || process.platform;
  if (platform === 'win32') {
    const nonce = options.nonce || crypto.randomBytes(16).toString('hex');
    if (!/^[A-Za-z0-9_-]+$/.test(name)) throw Error('Invalid IPC endpoint name');
    if (!/^[0-9a-fA-F]{16,128}$/.test(nonce)) throw Error('Invalid IPC endpoint nonce');
    return `\\\\.\\pipe\\ns2jb-${name}-${nonce.toLowerCase()}`;
  }
  return path.join(directory, name + '.sock');
}

async function secureLocalIpcPath(endpoint) {
  if (process.platform !== 'win32') await fs.chmod(endpoint, 0o600);
}

async function removeLocalIpcPath(endpoint) {
  // Windows named pipes are kernel objects and disappear when the server closes.
  if (process.platform !== 'win32') await fs.rm(endpoint, {force: true});
}

module.exports = {
  createPrivateTempDirectory,
  localIpcPath,
  secureLocalIpcPath,
  removeLocalIpcPath,
};
