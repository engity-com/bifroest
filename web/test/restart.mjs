import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { chromium } from 'playwright';
import { createServer } from 'vite';

// Own temporary profile only; never reuse a developer's normal browser profile.
const profile = await mkdtemp(join(tmpdir(), 'bifroest-browser-profile-'));
const server = await createServer({
  configFile: false,
  root: fileURLToPath(new URL('../', import.meta.url)),
  server: { host: '127.0.0.1', port: 0 },
  plugins: [{
    name: 'remember-restart-fixture',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url !== '/_remember-test.html') return next();
        res.setHeader('Content-Type', 'text/html');
        res.end('<!doctype html><html lang="en-US"><title>RememberMe storage test</title></html>');
      });
    },
  }],
});
let context;
let helper;
try {
  await server.listen();
  const address = server.httpServer.address();
  assert(address !== null && typeof address === 'object');
  const url = `http://127.0.0.1:${address.port}/_remember-test.html`;
  const open = async () => {
    context = await chromium.launchPersistentContext(profile, { headless: true });
    const page = await context.newPage();
    await page.goto(url);
    return page;
  };
  const initial = await open();
  const publicKey = await initial.evaluate(async () => {
    const { BrowserBinding } = await import('/src/remember/index.ts');
    const scope = { origin: 'https://app.example.org', slug: 'Work' };
    if (await BrowserBinding.load(scope) !== null) throw new Error('profile was not empty');
    const pending = await BrowserBinding.prepare(scope, { explicitOptIn: true });
    await pending.complete({ flow: 'work', sessionId: '70d5159d-a0e4-46ca-b011-c4f831f4ade0', bindingId: `bbr1.${'A'.repeat(43)}` });
    return pending.publicKey();
  });
  await context.close();
  const restarted = await open();
  const result = await restarted.evaluate(async () => {
    const { BrowserBinding } = await import('/src/remember/index.ts');
    const { decode64, encode64 } = await import('/src/remember/protocol.ts');
    const scope = { origin: 'https://app.example.org', slug: 'Work' };
    const restored = await BrowserBinding.load(scope);
    if (restored === null || restored.binding === null) throw new Error('persisted binding was lost');
    const publicKey = await restored.publicKey();
    const bytes = new TextEncoder().encode('bifroest-browser-remember-v1\0' + JSON.stringify({
      purpose: 'resume', ...scope, ...restored.binding, revision: 1, target: 'a'.repeat(64), publicKey,
      nonce: encode64(crypto.getRandomValues(new Uint8Array(32))), expiresAt: new Date(Date.now() + 60_000).toISOString(),
    }));
    const signature = decode64(await restored.sign(encode64(bytes), 'resume'), 64);
    const verifier = await crypto.subtle.importKey('raw', decode64(publicKey, 65), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return { publicKey, valid: await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, verifier, signature, bytes) };
  });
  assert.equal(result.publicKey, publicKey);
  assert.equal(result.valid, true);
  helper = spawn(process.env.BIFROEST_TEST_GO ?? 'go', ['-C', fileURLToPath(new URL('../../', import.meta.url)), 'run', fileURLToPath(new URL('proof-helper.go', import.meta.url))], {
    stdio: ['pipe', 'pipe', 'inherit'], timeout: 30_000,
  });
  const finished = new Promise((resolve, reject) => {
    helper.once('error', reject);
    helper.once('exit', code => code === 0 ? resolve() : reject(new Error('Go proof helper failed')));
  });
  const lines = createInterface({ input: helper.stdout })[Symbol.asyncIterator]();
  helper.stdin.write(JSON.stringify(publicKey) + '\n');
  const challenge = await lines.next();
  assert.equal(challenge.done, false);
  const signature = await restarted.evaluate(async challenge => {
    const { BrowserBinding } = await import('/src/remember/index.ts');
    const handle = await BrowserBinding.load({ origin: 'https://app.example.org', slug: 'Work' });
    if (handle === null) throw new Error('persisted browser keys missing');
    return handle.sign(challenge, 'resume');
  }, JSON.parse(challenge.value));
  helper.stdin.end(JSON.stringify(signature) + '\n');
  const verified = await lines.next();
  assert.equal(verified.done, false);
  assert.equal(JSON.parse(verified.value), true);
  await finished;
  console.log('PASS: actual Chromium restart retains non-exportable keys/encrypted selectors; the Go proof core accepts the persisted browser client signature.');
} finally {
  helper?.stdin.end();
  helper?.kill();
  await context?.close();
  await server.close();
  await rm(profile, { recursive: true, force: true });
}
