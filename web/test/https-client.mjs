import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright';

// Test driver only. Real fetches go directly to the Go HTTPS endpoint; no Vite
// proxy, fake HTTP transport or CLI is involved in browser actions.
const origin = process.argv[2];
assert.match(origin, /^https:\/\/app\.example\.org:[0-9]+$/);
const profile = await mkdtemp(join(tmpdir(), 'bifroest-https-browser-'));
let context;
try {
  const open = async () => {
    context = await chromium.launchPersistentContext(profile, {
      headless: true,
      ignoreHTTPSErrors: true, // Explicit owned self-signed fixture; no trust-store changes.
      args: ['--host-resolver-rules=MAP app.example.org 127.0.0.1', '--no-proxy-server'],
    });
    const page = await context.newPage();
    const response = await page.goto(`${origin}/_bifroest/test/client.html`);
    assert.equal(response.status(), 200);
    assert.equal(response.headers()['x-frame-options'], 'DENY');
    assert(response.headers()['content-security-policy'].includes("frame-ancestors 'none'"));
    return page;
  };
  const initial = await open();
  const binding = await initial.evaluate(async () => {
    const { BrowserClient, BrowserBinding } = await import('/_bifroest/test/client.js');
    const scope = { origin: location.origin, slug: 'Work' };
    const client = new BrowserClient(scope);
    // biome-ignore lint/suspicious/noDocumentCookie: Deliberately seed an unrelated cookie to prove it never authenticates API or WebSocket access.
    document.cookie =
      'existing-cookie=must-not-authenticate; Secure; SameSite=Strict; Path=/; Max-Age=300';
    const primary = await client.password('alice', 'correct');
    if (JSON.stringify(primary).includes('bwa1.')) {
      throw new Error('tab permission leaked through serialization');
    }
    await primary.remember({ explicitOptIn: true });
    const local = await BrowserBinding.load(scope);
    if (local === null || local.binding === null) {
      throw new Error('enrollment was not persisted');
    }
    if (localStorage.length !== 0 || sessionStorage.length !== 0) {
      throw new Error('persistent auth outside IndexedDB');
    }
    return local.binding;
  });
  await context.close();
  const restarted = await open();
  const result = await restarted.evaluate(async (binding) => {
    const { BrowserClient, BrowserBinding } = await import('/_bifroest/test/client.js');
    const scope = { origin: location.origin, slug: 'Work' };
    const client = new BrowserClient(scope);
    // biome-ignore lint/suspicious/noDocumentCookie: The restarted profile must also reject cookie-only WebSocket authentication.
    document.cookie =
      'existing-cookie=must-not-authenticate; Secure; SameSite=Strict; Path=/; Max-Age=300';
    const resumed = await client.resume();
    if (resumed === null || resumed.snapshot().principal !== 'alice') {
      throw new Error('saved browser login did not resume');
    }
    const local = await BrowserBinding.load(scope);
    if (JSON.stringify(local.binding) !== JSON.stringify(binding)) {
      throw new Error('resumption selected another persistent session');
    }
    const socketURL = `${location.origin.replace('https:', 'wss:')}/_bifroest/api/v1/terminal`;
    const unauthenticated = new WebSocket(socketURL, 'bifroest-terminal.v1');
    await Promise.race([
      new Promise((resolve, reject) => {
        unauthenticated.addEventListener(
          'open',
          () =>
            unauthenticated.send(
              JSON.stringify({
                type: 'open',
                slug: 'Work',
                accessToken: '',
                task: 'exec',
                command: 'run',
              }),
            ),
          { once: true },
        );
        unauthenticated.addEventListener('message', (event) => {
          if (typeof event.data === 'string' && JSON.parse(event.data).type === 'ready') {
            reject(new Error('a cookie authenticated a terminal'));
          }
        });
        unauthenticated.addEventListener('close', resolve, { once: true });
        unauthenticated.addEventListener('error', reject, { once: true });
      }),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('cookie-only terminal was not rejected')), 3000),
      ),
    ]);
    const socket = new WebSocket(socketURL, 'bifroest-terminal.v1');
    socket.binaryType = 'arraybuffer';
    const closed = new Promise((resolve) =>
      socket.addEventListener('close', resolve, { once: true }),
    );
    const started = new Promise((resolve, reject) => {
      socket.addEventListener('message', (event) => {
        if (event.data instanceof ArrayBuffer) {
          const bytes = new Uint8Array(event.data);
          if (
            bytes[0] === 0 &&
            new TextDecoder().decode(bytes.subarray(1)).includes('browser-client-execution-started')
          ) {
            resolve();
          }
        } else if (
          typeof event.data === 'string' &&
          ['error', 'exit'].includes(JSON.parse(event.data).type)
        ) {
          reject(new Error('terminal failed before backend execution'));
        }
      });
      socket.addEventListener(
        'close',
        () => reject(new Error('terminal closed before backend execution')),
        { once: true },
      );
    });
    await new Promise((resolve, reject) => {
      socket.addEventListener('open', resolve, { once: true });
      socket.addEventListener('error', reject, { once: true });
    });
    const ready = new Promise((resolve, reject) =>
      socket.addEventListener(
        'message',
        (event) => {
          if (typeof event.data !== 'string') {
            return;
          }
          const message = JSON.parse(event.data);
          if (message.type === 'ready') {
            resolve();
          } else {
            reject(new Error('terminal was not admitted'));
          }
        },
        { once: true },
      ),
    );
    socket.send(
      JSON.stringify({
        type: 'open',
        slug: 'Work',
        accessToken: resumed.terminalToken(),
        task: 'exec',
        command: 'run',
      }),
    );
    await ready;
    await started; // ready acknowledges admission, not successful provisioning/execution.
    // WebSocket browser APIs always attach ordinary cookies. They are not
    // authentication; the first open message remains the only access proof.
    const sibling = await client.password('alice', 'correct');
    let rejected = false;
    try {
      await new BrowserClient({
        origin: location.origin.replace('app.example.org', 'other.example.org'),
        slug: 'Work',
      }).password('must-not-leak', 'must-not-leak');
    } catch (error) {
      rejected = error.code === 'unavailable';
    }
    if (!rejected) {
      throw new Error('foreign-origin API destination was not rejected');
    }
    await resumed.logout();
    await Promise.race([
      closed,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('logout did not close its own terminal')), 3000),
      ),
    ]);
    if ((await BrowserBinding.load(scope)) !== null) {
      throw new Error('logout retained its own local binding');
    }
    const access = await fetch('/_bifroest/api/v1/access', {
      method: 'POST',
      credentials: 'omit',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sibling.terminalToken()}`,
      },
      body: JSON.stringify({ slug: 'Work' }),
    });
    if (access.status !== 200) {
      throw new Error('logout revoked an unrelated primary grant');
    }
    await sibling.remember({ explicitOptIn: true });
    await client.forgetRemembered();
    if ((await BrowserBinding.load(scope)) !== null) {
      throw new Error('proof revocation retained local binding');
    }
    if (localStorage.length !== 0 || sessionStorage.length !== 0) {
      throw new Error('persistent auth outside IndexedDB');
    }
    return { flow: binding.flow, sessionId: binding.sessionId };
  }, binding);
  console.log(JSON.stringify(result));
} finally {
  await context?.close();
  await rm(profile, { recursive: true, force: true });
}
