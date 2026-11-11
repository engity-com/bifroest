import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import { inspect } from 'node:util';
import { runInNewContext } from 'node:vm';
import { observeSingleRootDirectory } from './login-options-ui.mjs';
import { managementWire } from './management-wire.mjs';
import {
  assertCatalogRequestPrivacy,
  captureJsonResponse,
  installPreparationObserver,
} from './response-capture.mjs';

function wireFixture() {
  const page = new EventEmitter();
  const socket = new EventEmitter();
  socket.url = () => 'wss://app.example.org/api/v1/management/channel';
  const wire = managementWire(page);
  page.emit('websocket', socket);
  const sent = (value) => socket.emit('framesent', { payload: JSON.stringify(value) });
  const received = (value) => socket.emit('framereceived', { payload: JSON.stringify(value) });
  sent({ type: 'open', slug: 'Work', accessToken: 'PRIVATE-WIRE-PROOF' });
  received({
    type: 'ready',
    connectionId: '12345678-1234-1234-1234-123456789abc',
    keepAlive: { interval: '15s', locked: false },
  });
  const request = () =>
    sent({
      type: 'request',
      requestId: '1',
      action: 'management/auditlogs/list',
      fields: { limit: '20', after: '' },
    });
  const output = (value) => {
    const bytes = Buffer.from(JSON.stringify(value));
    const frame = Buffer.alloc(bytes.length + 8);
    frame.writeBigUInt64BE(1n);
    bytes.copy(frame, 8);
    socket.emit('framereceived', { payload: frame });
  };
  return { page, socket, wire, sent, received, request, output };
}

test('management capture observes real RPC identity and completion without fabricating HTTP grants', async () => {
  const f = wireFixture();
  const requests = [];
  f.wire.on('request', (request) => requests.push(request));
  const captured = captureJsonResponse(f.page, '/api/v1/management/auditlogs/list');
  let finished = false;
  void captured.then(() => {
    finished = true;
  });
  f.request();
  f.received({
    type: 'response',
    requestId: '1',
    status: 200,
    contentType: 'application/json; charset=utf-8',
  });
  f.output({ items: [] });
  await Promise.resolve();
  assert.equal(finished, false);
  f.received({ type: 'complete', requestId: '1' });
  assert.deepEqual(await captured, { status: 200, body: { items: [] } });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].transport, 'websocket');
  assert.equal(requests[0].method(), 'RPC');
  assert.deepEqual(requests[0].headers(), {});
  assert.equal(requests[0].slug(), 'Work');
  assert.equal(requests[0].channel(), '12345678-1234-1234-1234-123456789abc');
  assert.equal(JSON.stringify(requests).includes('PRIVATE-WIRE-PROOF'), false);
});

test('an interrupted management frame stream remains an incomplete capture, never optimistic success or a replay', async () => {
  const f = wireFixture();
  let requests = 0;
  f.wire.on('request', () => requests++);
  const captured = captureJsonResponse(f.page, '/api/v1/management/auditlogs/list');
  f.request();
  f.received({
    type: 'response',
    requestId: '1',
    status: 200,
    contentType: 'application/json; charset=utf-8',
  });
  f.output({ items: [] });
  f.socket.emit('close');
  assert.deepEqual(await captured, { error: 'response-capture-incomplete' });
  assert.equal(requests, 1);
});

test('catalog request privacy assertions never retain query or cookie secrets through error causes', () => {
  const secret = 'PRIVATE-CATALOG-REQUEST-SENTINEL';
  assert.doesNotThrow(() =>
    assertCatalogRequestPrivacy({
      url: () => 'https://app.example.org/api/v1/management/auditlogs/list',
      headers: () => ({ authorization: secret }),
    }),
  );
  for (const field of ['query', 'cookie']) {
    let failure;
    try {
      assertCatalogRequestPrivacy({
        url: () =>
          `https://app.example.org/api/v1/management/auditlogs/list${field === 'query' ? `?credential=${secret}` : ''}`,
        headers: () => (field === 'cookie' ? { cookie: secret } : {}),
      });
    } catch (error) {
      failure = error;
    }
    assert(failure instanceof assert.AssertionError, 'privacy violations must still fail');
    const outer = new Error('bounded catalog diagnostics', { cause: failure });
    assert.equal(inspect(outer, { depth: 8 }).includes(secret), false);
    assert.equal(JSON.stringify(failure).includes(secret), false);
  }
});

test('single-link discovery assertion failures never expose credential or query values', () => {
  const secret = 'PRIVATE-DISCOVERY-SENTINEL';
  for (const field of ['authorization', 'cookie', 'query']) {
    const callbacks = new Map();
    observeSingleRootDirectory({ on: (event, callback) => callbacks.set(event, callback) });
    const headers = {
      accept: 'application/json',
      ...(field === 'query' ? {} : { [field]: secret }),
    };
    let failure;
    try {
      callbacks.get('request')({
        method: () => 'GET',
        resourceType: () => 'fetch',
        headers: () => headers,
        url: () => `https://app.example.org/foo${field === 'query' ? `?private=${secret}` : ''}`,
      });
    } catch (error) {
      failure = error;
    }
    assert(failure instanceof assert.AssertionError);
    assert.equal(
      inspect(failure, { depth: 8 }).includes(secret),
      false,
      'failure details must contain only booleans, never request credentials',
    );
    assert.equal(JSON.stringify(failure).includes(secret), false);
  }
});

function fixture(options = {}) {
  const events = [];
  const target = { flow: 'worker', id: '12345678-1234-1234-1234-123456789abc' };
  const secret = 'PRIVATE-FIXTURE-SENTINEL';
  const body = options.body ?? { target, confirmationToken: secret };
  const response = {
    url: options.url ?? 'https://app.example.org/api/v1/management/sessions/prepare',
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
    { url: 'https://foreign.invalid/api/v1/management/sessions/prepare' },
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

function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

test('JSON capture registers before the action, reads immediately and joins request completion', async () => {
  const headers = deferred();
  const reading = deferred();
  const finished = deferred();
  const events = [];
  const pathname = '/api/v1/management/auditlogs/list';
  const body = { version: 1, operation: 'auditlogs.list', auditlogs: { items: [], next: '' } };
  let matches;
  const captured = captureJsonResponse(
    {
      waitForResponse(predicate, options) {
        events.push('registered');
        matches = predicate;
        assert.equal(options.timeout, 30_000);
        return headers.promise;
      },
    },
    pathname,
  );
  assert.deepEqual(events, ['registered']);
  const response = {
    url: () => `https://app.example.org${pathname}`,
    request: () => ({ method: () => 'POST' }),
    status: () => 200,
    async json() {
      events.push('body');
      reading.resolve();
      return body;
    },
    finished() {
      events.push('finished');
      return finished.promise;
    },
  };
  assert.equal(matches(response), true);
  assert.equal(matches({ ...response, request: () => ({ method: () => 'GET' }) }), false);
  assert.equal(matches({ ...response, url: () => 'https://app.example.org/other' }), false);
  events.push('action');
  headers.resolve(response);
  await reading.promise;
  assert.deepEqual(events, ['registered', 'action', 'body', 'finished']);
  let settled = false;
  void captured.then(() => {
    settled = true;
  });
  await Promise.resolve();
  assert.equal(settled, false, 'reading JSON alone cannot complete the capture');
  finished.resolve(null);
  const receipt = await captured;
  assert.equal(receipt.status, 200);
  assert(receipt.body === body, 'the observed body is retained without another request');
});

test('early JSON capture failures settle safely without raw exceptions, causes or partial bodies', async () => {
  const secret = 'PRIVATE-CATALOG-FIXTURE-SENTINEL';
  for (const failure of ['headers', 'body', 'finished', 'finished-value']) {
    let observations = 0;
    const captured = captureJsonResponse(
      {
        async waitForResponse() {
          observations++;
          if (failure === 'headers') {
            throw new Error(secret, { cause: secret });
          }
          return {
            status: () => 200,
            async json() {
              if (failure === 'body') {
                throw new Error(secret, { cause: secret });
              }
              return { private: secret };
            },
            async finished() {
              if (failure === 'finished') {
                throw new Error(secret, { cause: secret });
              }
              return failure === 'finished-value' ? new Error(secret) : null;
            },
          };
        },
      },
      '/api/v1/management/auditlogs/list',
    );
    // The consumer may still be awaiting UI work when capture fails.
    await Promise.resolve();
    await Promise.resolve();
    const receipt = await captured;
    assert.deepEqual(receipt, {
      error: failure === 'headers' ? 'response-capture-failed' : 'response-capture-incomplete',
    });
    assert.equal(observations, 1);
    assert.equal(inspect(receipt, { depth: 8 }).includes(secret), false);
    assert.equal(JSON.stringify(receipt).includes(secret), false);
  }
});

test('JSON header/body/completion observation shares the existing 30-second deadline', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const headers = deferred();
  const reading = deferred();
  const body = deferred();
  const finished = deferred();
  const captured = captureJsonResponse(
    { waitForResponse: () => headers.promise },
    '/api/v1/management/auditlogs/list',
  );
  t.mock.timers.tick(29_999);
  headers.resolve({
    status: () => 200,
    json() {
      reading.resolve();
      return body.promise;
    },
    finished: () => finished.promise,
  });
  await reading.promise;
  t.mock.timers.tick(1);
  assert.deepEqual(await captured, { error: 'response-capture-timeout' });
  body.resolve({ private: 'PRIVATE-LATE-CATALOG-FIXTURE' });
  finished.resolve(null);
  assert.deepEqual(await captured, { error: 'response-capture-timeout' });
});
