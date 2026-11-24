import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import { inspect } from 'node:util';
import { runInNewContext } from 'node:vm';
import { installDrawerDiagnostics } from './drawer-diagnostics.ts';
import {
    installLoginControlDiagnostics,
    type LoginControlDiagnostics,
    loginControlDiagnostics,
} from './login-control-diagnostics.ts';
import { observeSingleRootDirectory } from './login-options-ui.ts';
import { type ManagementRequest, managementWire } from './management-wire.ts';
import { required } from './required.ts';
import type { CaptureResponse } from './response-capture.ts';
import {
    assertCatalogRequestPrivacy,
    captureJsonResponse,
    installPreparationObserver,
} from './response-capture.ts';

function controlFixture({
    action = 'poll',
    failRead = false,
    fetchFailure = false,
}: {
    action?: 'poll' | 'reply';
    failRead?: boolean;
    fetchFailure?: boolean;
} = {}) {
    const secret = 'PRIVATE-LOGIN-KEY-ANSWER-CAUSE';
    const failure = new Error(secret, { cause: { password: secret } });
    const calls: (string | unknown[])[] = [];
    let reads = 0;
    const reader = {
        async read() {
            calls.push('read');
            if (failRead) {
                throw failure;
            }
            return ++reads === 1
                ? { value: new TextEncoder().encode(secret), done: false }
                : { done: true };
        },
        cancel(reason: unknown) {
            calls.push(['reader-cancel', reason]);
            return Promise.resolve();
        },
        releaseLock() {
            calls.push('release-lock');
        },
    };
    const response = {
        status: action === 'reply' ? 202 : 200,
        body: {
            getReader() {
                calls.push('get-reader');
                return reader;
            },
            cancel(reason: unknown) {
                calls.push(['body-cancel', reason]);
                return Promise.resolve();
            },
        },
    };
    const globals = {
        bifroestLoginControlDiagnostics: undefined as LoginControlDiagnostics | undefined,
        URL,
        location: { origin: 'https://app.example.org' },
        performance,
        fetch: async (...args: unknown[]) => {
            calls.push(['fetch', ...args]);
            if (fetchFailure) {
                throw failure;
            }
            return response;
        },
    };
    runInNewContext(`(${installLoginControlDiagnostics.toString()})()`, globals);
    const signal = new AbortController();
    const url = new URL(`/api/v1/login/${action}`, globals.location.origin);
    const options = {
        method: 'POST',
        signal: signal.signal,
        body: secret,
        headers: { Authorization: secret },
    };
    const events = () =>
        JSON.parse(
            JSON.stringify(required(globals.bifroestLoginControlDiagnostics).events),
        ) as LoginControlDiagnostics['events'];
    return { globals, signal, url, options, response, reader, calls, failure, secret, events };
}

for (const action of ['poll', 'reply'] as const) {
    test(`${action} diagnostics preserve response/reader identity and EOF ownership without reading, cloning or retaining secrets`, async () => {
        const f = controlFixture({ action });
        const response = await f.globals.fetch(f.url, f.options);
        assert.equal(response, f.response);
        assert.equal(f.calls.length, 1, 'headers observation must not read the body');
        const reader = response.body.getReader();
        assert.equal(reader, f.reader);
        const chunk = await reader.read();
        assert.equal(new TextDecoder().decode(chunk.value), f.secret);
        assert.equal((await reader.read()).done, true);
        reader.releaseLock();
        f.signal.abort(f.failure);
        const events = f.events();
        assert.deepEqual(
            events.map((event) => event.event),
            ['start', 'headers', 'get-reader', 'chunk', 'eof', 'release-lock', 'signal-abort'],
        );
        assert.equal(
            events.every((event) => event.action === action && event.sequence === 1),
            true,
        );
        assert.equal(
            events.find((event) => event.event === 'headers')?.status,
            action === 'reply' ? 202 : 200,
        );
        assert(events.every((event) => event.at >= performance.timeOrigin));
        assert.equal(required(events.at(-1)).eof, true);
        assert.equal(required(events.at(-1)).aborted, true);
        assert.equal(
            f.calls.filter((call) => Array.isArray(call) && call[0] === 'fetch').length,
            1,
        );
        assert.equal(f.calls.includes('read'), true);
        assert.equal(JSON.stringify(events).includes(f.secret), false);
    });

    test(`${action} diagnostics preserve original read/fetch failures and incomplete cancellation without replay`, async () => {
        const f = controlFixture({ action, failRead: true });
        const response = await f.globals.fetch(f.url, f.options);
        const reader = response.body.getReader();
        await assert.rejects(reader.read(), (error) => error === f.failure);
        await reader.cancel(f.failure);
        reader.releaseLock();
        await response.body.cancel(f.failure);
        f.signal.abort(f.failure);
        assert.deepEqual(
            f.events().map((event) => event.event),
            [
                'start',
                'headers',
                'get-reader',
                'read-failed',
                'reader-cancel',
                'release-lock',
                'body-cancel',
                'signal-abort',
            ],
        );
        assert.equal(
            f.events().every((event) => !event.eof),
            true,
        );
        assert.equal(JSON.stringify(f.events()).includes(f.secret), false);
        const lost = controlFixture({ action, fetchFailure: true });
        await assert.rejects(
            lost.globals.fetch(lost.url, lost.options),
            (error) => error === lost.failure,
        );
        assert.deepEqual(
            lost.events().map((event) => event.event),
            ['start', 'fetch-failed'],
        );
        assert.equal(lost.calls.length, 1);
        assert.deepEqual(
            await loginControlDiagnostics({
                evaluate: async () => {
                    throw f.failure;
                },
            }),
            { unavailable: true },
        );
    });
}

test('login-control observations are bounded and unrelated or foreign requests are untouched', async () => {
    const f = controlFixture();
    for (const url of [
        new URL('https://foreign.example/api/v1/login/poll'),
        new URL('https://foreign.example/api/v1/login/reply'),
        new URL('/api/v1/login/cancel', f.url),
        new URL(`${f.url}?${f.secret}`),
        new URL(`/api/v1/login/reply?${f.secret}`, f.url),
        new URL(`/api/v1/login/reply#${f.secret}`, f.url),
    ]) {
        assert.equal(await f.globals.fetch(url, f.options), f.response);
    }
    assert.equal(await f.globals.fetch(f.url, { ...f.options, method: 'GET' }), f.response);
    assert.deepEqual(f.events(), []);
    for (let index = 0; index < 150; index++) {
        await f.globals.fetch(f.url, f.options);
    }
    assert.equal(f.events().length, 256);
    assert.equal(required(f.globals.bifroestLoginControlDiagnostics).dropped(), 44);
    assert.equal(JSON.stringify(f.events()).includes(f.secret), false);
});

for (const action of ['poll', 'reply'] as const) {
    test(`${action} instrumentation works with the native response stream without consuming or substituting bytes`, async () => {
        const secret = 'PRIVATE-NATIVE-RESPONSE';
        const response = new Response(JSON.stringify({ answer: secret }), {
            status: action === 'reply' ? 202 : 200,
        });
        assert(response.body);
        const globals = {
            bifroestLoginControlDiagnostics: undefined as LoginControlDiagnostics | undefined,
            URL,
            location: { origin: 'https://app.example.org' },
            performance,
            fetch: async (..._args: unknown[]) => response,
        };
        runInNewContext(`(${installLoginControlDiagnostics.toString()})()`, globals);
        assert.equal(
            await globals.fetch(new URL(`/api/v1/login/${action}`, globals.location.origin), {
                method: 'POST',
            }),
            response,
        );
        const reader = response.body.getReader();
        const part = await reader.read();
        assert.equal(new TextDecoder().decode(part.value), JSON.stringify({ answer: secret }));
        assert.equal((await reader.read()).done, true);
        reader.releaseLock();
        assert.equal(
            JSON.stringify(required(globals.bifroestLoginControlDiagnostics).events).includes(
                secret,
            ),
            false,
        );
        assert.deepEqual(
            Array.from(
                required(globals.bifroestLoginControlDiagnostics).events,
                (event) => event.event,
            ),
            ['start', 'headers', 'get-reader', 'chunk', 'eof', 'release-lock'],
        );
    });
}

test('interleaved poll/reply requests have independent sequences for Playwright correlation', async () => {
    const f = controlFixture();
    for (const action of ['poll', 'reply', 'poll']) {
        await f.globals.fetch(new URL(`/api/v1/login/${action}`, f.url), f.options);
    }
    assert.deepEqual(
        f
            .events()
            .filter((event) => event.event === 'start')
            .map(({ action, sequence }) => [action, sequence]),
        [
            ['poll', 1],
            ['reply', 1],
            ['poll', 2],
        ],
    );
});

test('drawer diagnostics retain only bounded layout and ephemeral ownership, not DOM text, route or arbitrary CSS', () => {
    const secret = 'PRIVATE-DRAWER-OWNER-ROUTE-INPUT';
    let observe: (() => void) | undefined;
    const style = { display: 'block', visibility: 'visible', transform: 'none', secret };
    const pane = { getAttribute: () => 'true' };
    const link = {
        parentElement: null,
        secret,
        getBoundingClientRect: () => ({ width: 232, height: 40, x: -232, y: 10 }),
    };
    const paper = { ...link, querySelector: () => link };
    const toggle = { disabled: false, getAttribute: () => 'true', secret };
    const shell = {
        ...link,
        hidden: false,
        clientWidth: 900,
        closest: () => pane,
        getAttribute: () => 'temporary',
        querySelector: (selector: string) =>
            selector.includes('button') ? toggle : selector === '.MuiDrawer-paper' ? paper : null,
        textContent: secret,
        outerHTML: secret,
    };
    const globals = {
        bifroestDrawerDiagnostics: undefined as { snapshot(): unknown } | undefined,
        performance,
        document: { querySelectorAll: () => [shell], addEventListener() {} },
        getComputedStyle: () => style,
        ResizeObserver: class {
            observe() {}
        },
        MutationObserver: class {
            constructor(callback: () => void) {
                observe = callback;
            }
            observe() {}
        },
    };
    runInNewContext(`(${installDrawerDiagnostics.toString()})()`, globals);
    assert(observe);
    observe();
    const snapshot = () =>
        JSON.parse(JSON.stringify(required(globals.bifroestDrawerDiagnostics).snapshot()));
    const first = snapshot().events.at(-1).panes[0];
    assert.equal(first.owner, 1);
    assert.equal(first.active, true);
    assert.equal(first.expanded, true);
    assert.equal(first.link.x, -232);
    shell.hidden = true;
    style.display = 'none';
    observe();
    assert.equal(snapshot().events.at(-1).panes[0].shell.hidden, true);
    assert.equal(snapshot().events.at(-1).panes[0].shell.displayNone, true);
    for (let index = 0; index < 300; index++) {
        snapshot();
    }
    const result = snapshot();
    assert.equal(result.events.length, 256);
    assert(result.dropped > 0);
    assert.equal(JSON.stringify(result).includes(secret), false);
});

function wireFixture() {
    const page = new EventEmitter();
    const socket = Object.assign(new EventEmitter(), {
        url: () => 'wss://app.example.org/api/v1/management/channel',
    });
    const wire = managementWire(page);
    page.emit('websocket', socket);
    const sent = (value: unknown) => socket.emit('framesent', { payload: JSON.stringify(value) });
    const received = (value: unknown) =>
        socket.emit('framereceived', { payload: JSON.stringify(value) });
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
    const output = (value: unknown) => {
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
    const requests: ManagementRequest[] = [];
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
    assert.equal(required(requests[0]).transport, 'websocket');
    assert.equal(required(requests[0]).method(), 'RPC');
    assert.deepEqual(required(requests[0]).headers(), {});
    assert.equal(required(requests[0]).slug(), 'Work');
    assert.equal(required(requests[0]).channel(), '12345678-1234-1234-1234-123456789abc');
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
        let failure: unknown;
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
        let failure: unknown;
        try {
            callbacks.get('request')({
                method: () => 'GET',
                resourceType: () => 'fetch',
                headers: () => headers,
                url: () =>
                    `https://app.example.org/foo${field === 'query' ? `?private=${secret}` : ''}`,
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

function fixture(
    options: { body?: unknown; url?: string; status?: number; failure?: boolean } = {},
) {
    const events: string[] = [];
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
    const requests: unknown[][] = [];
    const globals = {
        testPreparationReceipt: undefined as unknown,
        URL,
        location: { origin: 'https://app.example.org' },
        async fetch(...args: unknown[]) {
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
    assert.equal(required(f.requests[0])[0], url);
    assert.equal(required(f.requests[0])[1], init);
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

function deferred<T = void>() {
    return Promise.withResolvers<T>();
}

test('JSON capture registers before the action, reads immediately and joins request completion', async () => {
    const headers = deferred<unknown>();
    const reading = deferred();
    const finished = deferred<Error | null>();
    const events: string[] = [];
    const pathname = '/api/v1/management/auditlogs/list';
    const body = { version: 1, operation: 'auditlogs.list', auditlogs: { items: [], next: '' } };
    let matches: ((response: CaptureResponse) => boolean) | undefined;
    const captured = captureJsonResponse(
        {
            waitForResponse(
                predicate: (response: CaptureResponse) => boolean,
                options: { timeout: number },
            ) {
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
    assert(matches);
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
            error:
                failure === 'headers' ? 'response-capture-failed' : 'response-capture-incomplete',
        });
        assert.equal(observations, 1);
        assert.equal(inspect(receipt, { depth: 8 }).includes(secret), false);
        assert.equal(JSON.stringify(receipt).includes(secret), false);
    }
});

test('JSON header/body/completion observation shares the existing 30-second deadline', async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const headers = deferred<unknown>();
    const reading = deferred();
    const body = deferred<unknown>();
    const finished = deferred<Error | null>();
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
