import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';
import { installPreparationObserver } from './response-capture.mjs';

function fixture(options = {}) {
  const events = [];
  const target = { flow: 'worker', id: '12345678-1234-1234-1234-123456789abc' };
  const secret = 'PRIVATE-FIXTURE-SENTINEL';
  const body = options.body ?? { target, confirmationToken: secret };
  const response = {
    url: options.url ?? 'https://app.example.org/_bifroest/api/v1/management/sessions/prepare',
    status: options.status ?? 202,
    clone() {
      events.push('clone');
      return {
        async json() {
          events.push('capture');
          if (options.failure) {
            throw new Error(secret, { cause: secret });
          }
          return body;
        },
      };
    },
    async json() {
      // Only the application may consume this original body.
      events.push('application-read');
      return body;
    },
  };
  const requests = [];
  const globals = {
    URL,
    location: { origin: 'https://app.example.org' },
    async fetch(...args) {
      events.push('fetch');
      requests.push(args);
      return response;
    },
  };
  // Exactly the same closure-free function is injected into the browser.
  runInNewContext(`(${installPreparationObserver.toString()})()`, globals);
  return {
    events,
    target,
    secret,
    response,
    globals,
    requests,
    receipt: () => JSON.parse(JSON.stringify(globals.testPreparationReceipt)),
  };
}

test('capture precedes original response delivery without replacing the browser transport or request', async () => {
  const f = fixture();
  const url = new URL(f.response.url);
  const init = {
    method: 'POST',
    credentials: 'omit',
    redirect: 'error',
    signal: new AbortController().signal,
    headers: { Authorization: f.secret },
  };
  const original = await f.globals.fetch(url, init);
  assert.equal(original, f.response);
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0][0], url);
  assert.equal(f.requests[0][1], init);
  assert.deepEqual(f.events, ['fetch', 'clone', 'capture']);
  await original.json();
  assert.deepEqual(f.receipt(), { status: 202, target: f.target });
  assert(!JSON.stringify(f.receipt()).includes(f.secret));
});

test('capture failures stay failed observations without raw errors, causes or a retry', async () => {
  const f = fixture({ failure: true });
  assert.equal(await f.globals.fetch(f.response.url), f.response);
  assert.deepEqual(f.receipt(), { status: 202, error: 'capture-failed' });
  assert.equal(f.requests.length, 1);
  assert(!JSON.stringify(f.receipt()).includes(f.secret));
  assert.throws(() => assert.deepEqual(f.receipt(), { status: 202, target: f.target }));
});

test('extra target metadata cannot be silently projected into a passing selector assertion', async () => {
  const f = fixture({
    body: {
      target: {
        flow: 'worker',
        id: '12345678-1234-1234-1234-123456789abc',
        credential: 'PRIVATE-FIXTURE-SENTINEL',
      },
    },
  });
  await f.globals.fetch(f.response.url);
  assert.deepEqual(f.receipt(), { status: 202, error: 'invalid-target' });
  assert(!JSON.stringify(f.receipt()).includes(f.secret));
});

test('only the first accepted same-origin preparation is observed; denial and foreign replies are unchanged', async () => {
  for (const options of [
    { status: 403 },
    { url: 'https://foreign.invalid/_bifroest/api/v1/management/sessions/prepare' },
  ]) {
    const f = fixture(options);
    assert.equal(await f.globals.fetch(f.response.url), f.response);
    assert.equal(f.globals.testPreparationReceipt, undefined);
    assert.deepEqual(f.events, ['fetch']);
  }
  const f = fixture();
  await f.globals.fetch(f.response.url);
  await f.globals.fetch(f.response.url);
  assert.equal(f.requests.length, 2);
  assert.equal(f.events.filter((event) => event === 'clone').length, 1);
});
