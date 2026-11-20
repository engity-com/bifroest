import assert from 'node:assert/strict';
import { test } from 'node:test';
import { publicNavigation } from './public-navigation.ts';

const target = 'https://app.example.org:443/#Work';

test('retries only the public document after a Chromium interface-change error', async () => {
    const calls: { url: string; timeout: number | undefined }[] = [];
    const result = await publicNavigation(
        {
            goto: async (url, options) => {
                calls.push({ url, timeout: options?.timeout });
                if (calls.length === 1) {
                    throw new Error('page.goto: net::ERR_NETWORK_CHANGED');
                }
                return null;
            },
        },
        target,
    );
    assert.equal(result, null);
    assert.equal(calls.length, 2);
    assert(calls.every((call) => call.url === target));
    assert.equal(calls[0]?.timeout, 30_000);
    assert(requiredTimeout(calls[1]?.timeout) <= 30_000);
});

function requiredTimeout(value: number | undefined): number {
    assert(value !== undefined && value > 0);
    return value;
}

test('does not retry successful navigation', async () => {
    let calls = 0;
    await publicNavigation(
        {
            goto: async () => {
                calls++;
                return null;
            },
        },
        target,
    );
    assert.equal(calls, 1);
});

test('never retries TLS or other navigation failures', async () => {
    for (const message of [
        'net::ERR_CERT_AUTHORITY_INVALID',
        'net::ERR_CONNECTION_RESET',
        'navigation timeout',
    ]) {
        let calls = 0;
        const failure = new Error(message);
        await assert.rejects(
            publicNavigation(
                {
                    goto: async () => {
                        calls++;
                        throw failure;
                    },
                },
                target,
            ),
            (error) => error === failure,
        );
        assert.equal(calls, 1);
    }
});

test('a repeated interface change remains a failed navigation', async () => {
    let calls = 0;
    const failure = new Error('page.goto: net::ERR_NETWORK_CHANGED');
    await assert.rejects(
        publicNavigation(
            {
                goto: async () => {
                    calls++;
                    throw failure;
                },
            },
            target,
        ),
        (error) => error === failure,
    );
    assert.equal(calls, 2);
});

test('the retry uses only the original navigation budget', async (t) => {
    let now = 0;
    t.mock.method(Date, 'now', () => now);
    const timeouts: (number | undefined)[] = [];
    await publicNavigation(
        {
            goto: async (_, options) => {
                timeouts.push(options?.timeout);
                if (timeouts.length === 1) {
                    now = 29_900;
                    throw new Error('page.goto: net::ERR_NETWORK_CHANGED');
                }
                return null;
            },
        },
        target,
    );
    assert.deepEqual(timeouts, [30_000, 100]);
});

test('an exhausted navigation budget cannot start another attempt', async (t) => {
    let now = 0;
    t.mock.method(Date, 'now', () => now);
    let calls = 0;
    const failure = new Error('page.goto: net::ERR_NETWORK_CHANGED');
    await assert.rejects(
        publicNavigation(
            {
                goto: async () => {
                    calls++;
                    now = 30_000;
                    throw failure;
                },
            },
            target,
        ),
        (error) => error === failure,
    );
    assert.equal(calls, 1);
});

test('rejects API paths, credentials, query strings and plaintext before navigating', async () => {
    for (const url of [
        'https://app.example.org/api/v1/login/password',
        'https://app.example.org/api/v1/ssh',
        'https://user:password@app.example.org/',
        'https://app.example.org/?token=secret',
        'https://app.example.org/?',
        'http://app.example.org/',
    ]) {
        let calls = 0;
        await assert.rejects(
            publicNavigation(
                {
                    goto: async () => {
                        calls++;
                        return null;
                    },
                },
                url,
            ),
            /Expected a public HTTPS root document/u,
        );
        assert.equal(calls, 0);
    }
});
