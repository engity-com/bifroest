import assert from 'node:assert/strict';
import {
  activeAccess,
  assertUiPreferences,
  changeTheme,
  chooseLoginMethod,
  logoutAccess,
  notification,
  settledLogin,
} from './workspace-ui.mjs';

export async function exercisePreferences(page) {
  const requests = [];
  let keyDownloads = 0;
  page.on('request', (request) => {
    if (request.url().endsWith('/browser-key.wasm')) {
      keyDownloads++;
    }
    if (
      /\/api\/v1\/login\/(password|interactive|public-key)$/u.test(new URL(request.url()).pathname)
    ) {
      const { slug, user } = request.postDataJSON();
      requests.push({ slug, user });
    }
  });
  const input = () => page.getByLabel('User name', { exact: true });
  const dialog = () => page.getByRole('dialog', { name: 'Sign in', exact: true });
  const pref = (slug) =>
    page.evaluate(
      (slug) => localStorage.getItem(`bifroest-ui-v1:username:${encodeURIComponent(slug)}`),
      slug,
    );
  assert.equal(await input().inputValue(), '');
  assert.equal(await input().evaluate((node) => node.required), true);
  await page.getByLabel('Password', { exact: true }).fill('correct');
  await dialog().getByRole('button', { name: 'Sign in', exact: true }).click();
  assert.equal(await input().evaluate((node) => node.validity.valueMissing), true);
  assert.deepEqual(requests, []);
  await input().fill('   ');
  await page
    .locator('.login-form')
    .evaluate((form) =>
      form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })),
    );
  await page.getByText('Enter a user name before signing in.', { exact: true }).waitFor();
  assert.deepEqual(
    requests,
    [],
    'the explicit submit guard also refuses empty/whitespace names before authentication',
  );
  await input().fill('');
  await chooseLoginMethod(page, 'SSH key login');
  await page.getByLabel('Private key file (local only)', { exact: true }).setInputFiles({
    name: 'local-validation-fixture',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from('not a real private key'),
  });
  await page
    .getByLabel('Key passphrase (optional, local only)', { exact: true })
    .fill('PRIVATE-VALIDATION-SENTINEL');
  await dialog().getByRole('button', { name: 'Sign in', exact: true }).click();
  assert.equal(keyDownloads, 0, 'a missing username must not even start local key import');
  assert.deepEqual(requests, []);
  await chooseLoginMethod(page, 'Password login');

  async function password(user, value = 'correct') {
    await input().fill(user);
    await page.getByLabel('Password', { exact: true }).fill(value);
    await dialog().getByRole('button', { name: 'Sign in', exact: true }).click();
  }
  await password('alice');
  await settledLogin(page, 'alice');
  assert.equal(await pref('Work'), 'alice');
  await changeTheme(page, 'Dark');
  const count = requests.length;
  await page.reload();
  await dialog().waitFor();
  await page.locator('html[data-color-scheme="dark"]').waitFor();
  assert.equal(await input().inputValue(), 'alice');
  assert.equal(requests.length, count, 'stored preferences cannot trigger a login');
  assert.equal(await page.getByRole('tab', { includeHidden: true }).count(), 0);
  await password('rejected-user');
  await page.getByText('Access was denied.', { exact: false }).waitFor();
  assert.equal(
    await pref('Work'),
    'alice',
    'a denied name must not replace a successful preference',
  );

  async function flow(slug) {
    await page.getByLabel('Slug', { exact: true }).click();
    await page.getByRole('option', { name: slug, exact: true }).click();
    await page.waitForFunction(
      (slug) =>
        document
          .querySelector('.login-dialog [data-login-ready="true"]')
          ?.getAttribute('data-login-scope') === slug,
      slug,
    );
    assert.equal(new URL(page.url()).pathname, `/${slug}`);
  }
  await flow('Other');
  assert.equal(
    await input().inputValue(),
    '',
    'a different flow cannot adopt the other account preference',
  );
  await page.getByRole('checkbox', { name: 'Remember this browser', exact: true }).check();
  await password('bob');
  await settledLogin(page, 'bob');
  await activeAccess(page, 'bob');
  assert.equal(await pref('Other'), 'bob');
  assert.equal(await pref('Work'), 'alice');
  await page.getByRole('button', { name: 'New connection', exact: true }).click();
  await dialog().waitFor();
  assert.equal(await input().inputValue(), 'bob');
  const beforeNameFree = requests.length;
  await flow('NameFree');
  assert.equal(await input().count(), 0, 'deliberately name-free flows still omit this input');
  await dialog()
    .getByText('No sign-in method is available for this access link.', { exact: true })
    .waitFor();
  assert.equal(await dialog().getByLabel('Password', { exact: true }).count(), 0);
  assert.equal(
    requests.length,
    beforeNameFree,
    'an impossible method cannot submit a hidden preferred name',
  );
  assert.equal(await pref('NameFree'), null);
  await dialog().getByRole('button', { name: 'Close', exact: true }).click();
  await dialog().waitFor({ state: 'hidden' });
  await logoutAccess(page);
  await notification(page, 'Logout confirmed.');
  await page.reload();
  await dialog().waitFor({ state: 'visible' });
  assert.equal(new URL(page.url()).pathname, '/NameFree');
  await flow('Work');
  assert.equal(await input().inputValue(), 'alice');
  assert.equal(
    await page.getByRole('button', { name: 'Use saved access', exact: true }).count(),
    0,
  );
  assert.equal(
    await page.evaluate(async () => {
      const database = await new Promise((resolve, reject) => {
        const request = indexedDB.open('bifroest-browser-remember-v1');
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(new Error('storage'));
      });
      try {
        return await new Promise((resolve, reject) => {
          const request = database
            .transaction('bindings', 'readonly')
            .objectStore('bindings')
            .count();
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(new Error('storage'));
        });
      } finally {
        database.close();
      }
    }),
    0,
    'confirmed logout removes the registration, not the independent UI preferences',
  );
  await assertUiPreferences(page);
}
