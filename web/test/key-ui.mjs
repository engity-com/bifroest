import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { settledLogin } from './workspace-ui.mjs';

export async function exerciseKey(page, file, logout) {
  const fixture = JSON.parse(await readFile(file, 'utf8'));
  const posts = [];
  let stage = 'boot';
  const failures = [];
  const publicDownloads = [];
  let workerPolicy;
  page.on('request', (request) => {
    if (request.method() === 'POST') {
      posts.push({ url: request.url(), body: request.postData() ?? '' });
    }
    if (request.url().endsWith('/browser-key.wasm')) {
      let ownedByTab = false;
      try {
        ownedByTab = request.frame() === page.mainFrame();
      } catch {}
      publicDownloads.push(ownedByTab);
    }
  });
  page.on('response', (response) => {
    if (response.url().endsWith('/browser-key-worker.js')) {
      workerPolicy = response.headers()['content-security-policy'];
    }
  });
  page.on('response', (response) => {
    if (response.status() >= 400) {
      failures.push({ path: new URL(response.url()).pathname, status: response.status() });
    }
  });
  const choose = async () => {
    await page.getByText('SSH key login', { exact: true }).click();
    await page.getByLabel('User name', { exact: true }).fill('alice');
  };
  const select = async (name, password = fixture.passphrase, certificate) => {
    await page.getByLabel('User name', { exact: true }).fill('alice');
    await page.getByLabel('Private key file (local only)', { exact: true }).setInputFiles({
      name: 'local-key',
      mimeType: 'application/octet-stream',
      buffer: Buffer.from(fixture[name]),
    });
    await page.getByLabel('Key passphrase (optional, local only)', { exact: true }).fill(password);
    if (certificate) {
      await page.getByLabel('SSH user certificate (optional)', { exact: true }).setInputFiles({
        name: 'local-cert.pub',
        mimeType: 'text/plain',
        buffer: Buffer.from(fixture[certificate]),
      });
    }
  };
  const submit = async () => {
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  };
  const signed = async () => {
    try {
      await settledLogin(page, 'alice');
    } catch (error) {
      throw new Error(
        JSON.stringify({
          stage,
          failures,
          notices: await page.getByRole('status').allTextContents(),
        }),
        { cause: error },
      );
    }
    assert.equal(page.workers().length, 0, 'signing worker must be retired before access is shown');
  };
  await choose();
  const form = page.locator('form').first();
  assert.equal(
    await form.getAttribute('method'),
    'dialog',
    'a fallback native submit cannot upload key/passphrase fields',
  );
  assert.equal(await page.locator('#key-passphrase').getAttribute('name'), null);
  assert.equal(await page.locator('#key-private').getAttribute('name'), null);

  // Public-download cancellation must precede any secret-key worker/import/API login.
  let entered;
  const blocked = new Promise((resolve) => {
    entered = resolve;
  });
  await page.route('**/browser-key.wasm', async (route) => {
    entered(route);
  });
  await select('ed');
  await submit();
  const route = await blocked;
  assert.equal(
    page.workers().length,
    0,
    'a blocked public download must not create a secret-key worker',
  );
  await page.getByRole('button', { name: 'Cancel', exact: true }).last().click();
  await route.abort().catch(() => undefined);
  await page.unroute('**/browser-key.wasm');
  assert.equal(posts.length, 0);
  assert.equal(page.workers().length, 0);

  await select('ed', 'wrong passphrase');
  await submit();
  await page
    .getByText('The local key could not be imported or signed.', { exact: false })
    .waitFor();
  assert.equal(posts.length, 0, 'a failed local decrypt must not contact the authentication API');
  assert.equal(
    await page.getByLabel('Key passphrase (optional, local only)', { exact: true }).inputValue(),
    '',
  );
  assert.equal(await page.locator('#key-private').evaluate((input) => input.files.length), 0);

  await select('ed');
  await page.getByRole('checkbox', { name: 'Remember this browser', exact: true }).check();
  await submit();
  await signed();
  await page.getByText('RememberMe setup confirmed for this browser.', { exact: true }).waitFor();
  assert(
    workerPolicy.includes("'wasm-unsafe-eval'") &&
      !workerPolicy.includes("'unsafe-eval'") &&
      workerPolicy.includes("worker-src 'none'"),
  );
  const records = await page.evaluate(async () => {
    const names = await indexedDB.databases();
    const database = await new Promise((resolve, reject) => {
      const request = indexedDB.open('bifroest-browser-remember-v1');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error('storage'));
    });
    try {
      const values = await new Promise((resolve, reject) => {
        const request = database.transaction('bindings').objectStore('bindings').getAll();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(new Error('storage'));
      });
      return {
        names: names.map((entry) => entry.name),
        keys: values.map((value) => Object.keys(value).sort()),
      };
    } finally {
      database.close();
    }
  });
  assert.deepEqual(records.names, ['bifroest-browser-remember-v1']);
  assert.deepEqual(records.keys, [
    ['ciphertext', 'encryption', 'generation', 'iv', 'signing', 'tag'],
  ]);
  await page.reload();
  await page.getByRole('button', { name: 'Use saved access', exact: true }).click();
  await signed();
  await logout(page);
  await choose();
  await select('ed', fixture.passphrase, 'expiredCertificate');
  await submit();
  await page.getByText('Access was denied.', { exact: false }).waitFor();
  assert.equal(page.workers().length, 0);
  stage = 'certificate/pty';
  await select('ed', fixture.passphrase, 'certificate');
  await submit();
  await signed();
  await logout(page);
  for (const name of ['plain']) {
    stage = name;
    await select(name, name === 'plain' ? '' : fixture.passphrase);
    await submit();
    await signed();
    await logout(page);
  }
  for (const request of posts) {
    assert.equal(new URL(request.url).search, '');
    assert(
      !request.body.includes('-----BEGIN') &&
        !request.body.includes(fixture.passphrase) &&
        !request.body.includes('wrong passphrase'),
    );
    const body = JSON.parse(request.body);
    assert(!Object.hasOwn(body, 'privateKey') && !Object.hasOwn(body, 'passphrase'));
    if (request.url.endsWith('/login/public-key')) {
      assert.deepEqual(Object.keys(body).sort(), ['publicKey', 'slug', 'user']);
    }
  }
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert(
    publicDownloads.length > 0 && publicDownloads.every(Boolean),
    'public WASM requests must be owned by the tab, not a retiring secret worker',
  );
}

// Each algorithm / denied-PTY scenario owns its server and normal request budget.
// The protocol/recovery test above must not become an artificial many-login burst
// that spends the production per-peer asset/API limit before its last algorithm.
export async function exerciseKeyVariant(page, file, variant, logout) {
  const fixture = JSON.parse(await readFile(file, 'utf8'));
  const denied = variant === 'no-pty';
  let sockets = 0;
  page.on('websocket', () => {
    sockets++;
  });
  page.on('request', (request) => {
    const body = request.postData() ?? '';
    assert(
      !body.includes('-----BEGIN') && !body.includes(fixture.passphrase),
      'private material must stay in this tab',
    );
  });
  await page.getByText('SSH key login', { exact: true }).click();
  await page.getByLabel('User name', { exact: true }).fill('alice');
  await page.getByLabel('Private key file (local only)', { exact: true }).setInputFiles({
    name: 'local-key',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from(fixture[denied ? 'ed' : variant]),
  });
  await page
    .getByLabel('Key passphrase (optional, local only)', { exact: true })
    .fill(fixture.passphrase);
  if (denied) {
    await page.getByLabel('SSH user certificate (optional)', { exact: true }).setInputFiles({
      name: 'no-pty.pub',
      mimeType: 'text/plain',
      buffer: Buffer.from(fixture.noPtyCertificate),
    });
  }
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  if (denied) {
    await page.getByRole('heading', { name: 'Signed in as alice', exact: true }).waitFor();
    await page.getByRole('dialog', { name: 'Sign in', exact: true }).waitFor({ state: 'hidden' });
    await page.locator('[data-terminal-phase="interrupted"]').waitFor();
    assert.equal(await page.locator('[data-terminal-phase="exited"]').count(), 0);
  } else {
    await settledLogin(page, 'alice');
  }
  assert.equal(
    sockets,
    1,
    'one confirmed login makes one shell attempt, with no PTY fallback or retry',
  );
  assert.equal(page.workers().length, 0);
  await logout(page);
  assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
}
