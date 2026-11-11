import { spawnSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';

if (process.versions.node !== '26.9.0') {
  throw new Error('Native WebCrypto tests require the MISE-pinned Node runtime');
}
// Check/warm the pinned runtime before concurrent Go package startup. The real
// Go/WebCrypto possession test still creates independent keys and must run;
// this preflight is neither its substitute nor a credential/export operation.
await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
  'sign',
  'verify',
]);
await webcrypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
const result = spawnSync('mise', ['run', 'test:go'], {
  cwd: fileURLToPath(new URL('../../', import.meta.url)),
  env: { ...process.env, BIFROEST_TEST_NODE: process.execPath },
  stdio: 'inherit',
});
if (result.error !== undefined) {
  throw result.error;
}
process.exitCode = result.status ?? 1;
