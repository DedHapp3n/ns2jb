#!/usr/bin/env node
const fs = require('node:fs/promises');
const net = require('node:net');
const path = require('node:path');
const {chooseHost} = require('./run.cjs');
const {
  createPrivateTempDirectory,
  localIpcPath,
  secureLocalIpcPath,
  removeLocalIpcPath,
} = require('./engine/shared/local-ipc.cjs');

const PORT = 39380;

function requireNode22() {
  const major = Number(process.versions.node.split('.')[0]);
  if (!Number.isInteger(major) || major < 22)
    throw Error('Node.js 22 or newer is required; found ' + process.version);
  return process.version;
}

async function checkTempDirectory() {
  const directory = await createPrivateTempDirectory('ns2jb-preflight-');
  const marker = path.join(directory, 'marker.txt');
  try {
    await fs.writeFile(marker, 'ok\n');
    if ((await fs.readFile(marker, 'utf8')) !== 'ok\n')
      throw Error('Temporary-directory readback failed');
    return directory;
  } finally {
    await fs.rm(directory, {recursive: true, force: true});
  }
}

async function checkLocalIpc() {
  const directory = await createPrivateTempDirectory('ns2jb-ipc-preflight-');
  const endpoint = localIpcPath(directory, 'preflight');
  const server = net.createServer(socket => {
    socket.setEncoding('utf8');
    socket.once('data', data => {
      if (data === 'ping\n') socket.end('pong\n');
      else socket.destroy(Error('Unexpected preflight request'));
    });
  });
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(endpoint, resolve);
    });
    await secureLocalIpcPath(endpoint);
    const reply = await new Promise((resolve, reject) => {
      const client = net.createConnection(endpoint);
      let data = '';
      client.setEncoding('utf8');
      client.setTimeout(5000, () => client.destroy(Error('Local IPC preflight timed out')));
      client.once('error', reject);
      client.once('connect', () => client.write('ping\n'));
      client.on('data', chunk => { data += chunk; });
      client.once('end', () => resolve(data));
    });
    if (reply !== 'pong\n') throw Error('Local IPC reply did not match');
    return endpoint;
  } finally {
    await new Promise(resolve => server.close(resolve));
    await removeLocalIpcPath(endpoint);
    await fs.rm(directory, {recursive: true, force: true});
  }
}

async function checkTcpPort(host) {
  const server = net.createServer();
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen({host, port: PORT, exclusive: true}, resolve);
    });
    const address = server.address();
    return {host: address.address, port: address.port};
  } finally {
    if (server.listening) await new Promise(resolve => server.close(resolve));
  }
}

async function main(args = process.argv.slice(2)) {
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node host-check.cjs [computer-IP]');
    return;
  }
  const host = await chooseHost(args);
  const result = {
    platform: process.platform,
    node: requireNode22(),
    host,
    port: PORT,
    checks: {},
  };

  result.checks.tempDirectory = await checkTempDirectory().then(() => 'ok');
  result.checks.localIpc = await checkLocalIpc().then(() => 'ok');
  result.checks.tcp39380 = await checkTcpPort(host).then(() => 'ok');

  console.log(JSON.stringify(result, null, 2));
  if (host.startsWith('127.'))
    console.log('NOTE: loopback is suitable for CI/self-test only; the Switch cannot reach it.');
  if (process.platform === 'win32')
    console.log('Windows: allow Node.js/TCP 39380 only on the Private network profile used by the Switch.');
  console.log('Host preflight passed. No Switch-side action was performed.');
}

module.exports = {PORT, requireNode22, checkTempDirectory, checkLocalIpc, checkTcpPort, main};

if (require.main === module) main().catch(error => {
  console.error('Host preflight failed: ' + error.message);
  process.exitCode = 1;
});
