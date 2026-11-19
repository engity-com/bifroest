import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import type { Page } from 'playwright';
import { observePublicKeyWasm } from './public-wasm-diagnostics.ts';
import { required } from './required.ts';

class Session extends EventEmitter {
    commands: string[] = [];
    detached = false;
    async send(command: string) {
        this.commands.push(command);
        return command === 'Page.getFrameTree' ? { frameTree: { frame: { id: 'main' } } } : {};
    }
    async detach() {
        this.detached = true;
    }
}
const origin = 'https://app.example.org:8443';
const url = `${origin}/assets/browser-key.wasm`;

test('public WASM diagnostics retain only bounded transport observations, never credentials or arbitrary errors', async () => {
    const session = new Session();
    const page = { context: () => ({ newCDPSession: async () => session }) };
    let stage = 'login';
    const observer = await observePublicKeyWasm(page as unknown as Page, origin, () => stage);
    const start = (requestId: string, address = url, method = 'GET') =>
        session.emit('Network.requestWillBeSent', {
            requestId,
            frameId: 'main',
            request: {
                url: address,
                method,
                headers: { Authorization: 'never-log-secret' },
                postData: 'never-log-secret',
            },
            type: 'Fetch',
            initiator: { type: 'script', stack: { secret: 'never-log-secret' } },
        });
    start('ignored', `${origin}/api/v1/login/public-key`, 'POST');
    start('wrong-origin', `https://other.example/assets/browser-key.wasm`);
    start('not-get', url, 'POST');
    assert.equal(observer.events.length, 0);
    start('one');
    session.emit('Network.responseReceived', {
        requestId: 'one',
        response: {
            status: 200,
            protocol: 'h2',
            mimeType: 'application/wasm',
            headers: { 'Set-Cookie': 'never-log-secret' },
        },
    });
    session.emit('Network.dataReceived', {
        requestId: 'one',
        dataLength: 123,
        data: 'never-log-secret',
    });
    stage = 'connected';
    session.emit('Network.loadingFinished', { requestId: 'one', encodedDataLength: 155 });
    start('two', `${url}?never-log-secret`);
    session.emit('Network.loadingFailed', {
        requestId: 'two',
        canceled: true,
        errorText: 'net::ERR_ABORTED',
    });
    start('three');
    session.emit('Network.loadingFailed', { requestId: 'three', errorText: 'never-log-secret' });
    assert.deepEqual(session.commands, ['Page.getFrameTree', 'Network.enable']);
    assert.equal(required(observer.events[0]).owner, 'tab');
    assert.deepEqual(observer.events[2], {
        request: 1,
        type: 'finished',
        stage: 'connected',
        observedMs: required(observer.events[2]).observedMs,
        decodedBytes: 123,
        encodedBytes: 155,
    });
    assert.equal(required(observer.events[3]).hasQuery, true);
    assert.equal(required(observer.events[4]).error, 'net::ERR_ABORTED');
    assert.equal(required(observer.events[5]).error, undefined);
    assert.equal(required(observer.events[6]).error, 'network-error');
    assert(!JSON.stringify(observer.events).includes('never-log-secret'));
    for (let index = 0; index < 200; index++) {
        session.emit('Network.loadingFinished', { requestId: 'one', encodedDataLength: 155 });
    }
    assert.equal(observer.events.length, 128);
    await observer.close();
    assert.equal(session.detached, true);
});
