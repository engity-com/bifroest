import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { recordingSourceMediaType, transferMediaType } from '../src/artifacts/protocol';
import type { ManagementConnection } from '../src/management/channel';
import { ManagementResponseBuffer } from '../src/management/response-buffer';
import { WebAccess } from '../src/remember/client';
import { Http } from '../src/remember/http';
import type { Socket } from '../src/terminal/socket';

const id = '70d5159d-a0e4-46ca-b011-c4f831f4ade0';
class FakeSocket implements Socket {
    binaryType: BinaryType = 'blob';
    protocol = 'bifroest-management.v1';
    readyState = 1;
    bufferedAmount = 0;
    onopen: Socket['onopen'] = null;
    onmessage: Socket['onmessage'] = null;
    onerror: Socket['onerror'] = null;
    onclose: Socket['onclose'] = null;
    sent: Record<string, unknown>[] = [];
    closes = 0;
    send(data: string | Uint8Array<ArrayBuffer>) {
        if (typeof data !== 'string') {
            throw new Error('management must not send terminal input');
        }
        this.sent.push(JSON.parse(data) as Record<string, unknown>);
    }
    close() {
        this.closes++;
        this.readyState = 3;
    }
    json(value: unknown) {
        this.onmessage?.(new MessageEvent('message', { data: JSON.stringify(value) }));
    }
    ready() {
        this.onopen?.(new Event('open'));
        this.json({
            type: 'ready',
            connectionId: id,
            keepAlive: { interval: '15s', locked: false },
        });
    }
    output(requestId: string, bytes: Uint8Array) {
        const data = new Uint8Array(bytes.length + 8);
        new DataView(data.buffer).setBigUint64(0, BigInt(requestId));
        data.set(bytes, 8);
        this.onmessage?.(new MessageEvent('message', { data: data.buffer }));
    }
    response(requestId: string, value: unknown, status = 200) {
        this.json({
            type: 'response',
            requestId,
            status,
            contentType: 'application/json; charset=utf-8',
        });
        if (status !== 204) {
            this.output(requestId, new TextEncoder().encode(JSON.stringify(value)));
        }
        this.json({ type: 'complete', requestId });
    }
}
const connections: ManagementConnection[] = [];
beforeEach(() => vi.useFakeTimers());
afterEach(() => {
    for (const connection of connections.splice(0)) {
        connection.disconnect();
    }
    vi.useRealTimers();
    vi.restoreAllMocks();
});
function fixture() {
    const scope = { origin: 'https://app.example.org:8443', slug: 'Work' };
    const transport = vi.fn();
    const token = `bwa1.${'A'.repeat(43)}`;
    const access = new WebAccess(
        new Http(scope, transport),
        {
            scope,
            principal: 'alice',
            environment: 'management',
            terminalAvailable: false,
            expiresAt: new Date(Date.now() + 1000).toISOString(),
            accessToken: token,
        },
        null,
    );
    const socket = new FakeSocket();
    const factory = vi.fn(() => socket);
    const changed = vi.fn();
    const connection = access.openManagement(changed, {}, factory);
    connections.push(connection);
    return { scope, access, socket, connection, transport, factory, token };
}
describe('admitted actor-owned management connection', () => {
    it('preserves an actual 429 as rate-limited without closing, retrying, or using an HTTP fallback', async () => {
        const { access, socket, connection, transport, factory } = fixture();
        socket.ready();
        const pending = access.managementAuditEvents('default');
        const observed = expect(pending).rejects.toMatchObject({ code: 'rate-limited' });
        await Promise.resolve();
        await Promise.resolve();
        socket.response('1', { error: 'web request limit reached' }, 429);
        await observed;
        await vi.advanceTimersByTimeAsync(5000);
        expect(socket.sent.filter((frame) => frame.type === 'request')).toHaveLength(1);
        expect(connection.connected()).toBe(true);
        expect(factory).toHaveBeenCalledOnce();
        expect(transport).not.toHaveBeenCalled();
        const refresh = access.managementAuditEvents('default');
        await Promise.resolve();
        await Promise.resolve();
        socket.response('2', {
            version: 1,
            operation: 'audit-events.list',
            auditEvents: { items: [], next: '', skipped: 0 },
            auditEventSource: {
                auditlog: 'default',
                encrypted: true,
                sensitive: false,
                verification: 'server-overview',
            },
        });
        await expect(refresh).resolves.toMatchObject({ items: [], source: { encrypted: true } });
        expect(socket.sent.filter((frame) => frame.type === 'request')).toHaveLength(2);
        expect(factory).toHaveBeenCalledOnce();
        expect(transport).not.toHaveBeenCalled();
    });
    it('streams a source on the existing actor channel, excludes parallel transfers and never falls back to HTTP', async () => {
        const { access, socket, transport, factory } = fixture();
        socket.ready();
        const pending = access.openRecordingSource('default');
        await Promise.resolve();
        await Promise.resolve();
        expect(socket.sent.at(-1)).toEqual({
            type: 'request',
            requestId: '1',
            action: 'management/artifacts/recordings',
            fields: { auditlog: 'default' },
        });
        socket.json({
            type: 'response',
            requestId: '1',
            status: 200,
            contentType: recordingSourceMediaType,
        });
        socket.json({ type: 'source-start', requestId: '1', source: 'default', total: 1 });
        const stream = await pending;
        await expect(
            access.downloadArtifact({ kind: 'recording', auditlog: 'default', id }),
        ).rejects.toMatchObject({ code: 'busy' });
        const next = stream.next();
        await Promise.resolve();
        expect(socket.sent.at(-1)).toEqual({ type: 'source-next', requestId: '1', index: '1' });
        socket.json({
            type: 'source-entry',
            requestId: '1',
            index: 1,
            recordingId: id,
            status: 200,
            contentType: transferMediaType,
            encrypted: false,
            recipient: '',
        });
        socket.output('1', new Uint8Array([1, 2, 3]));
        socket.json({ type: 'source-entry-complete', requestId: '1', index: 1 });
        const received = await next;
        expect(received.done).toBe(false);
        socket.json({ type: 'complete', requestId: '1' });
        await stream.closed;
        expect((await stream.next()).done).toBe(true);
        expect(transport).not.toHaveBeenCalled();
        expect(factory).toHaveBeenCalledOnce();
        const after = access.managementFlows();
        await Promise.resolve();
        socket.response('2', {
            version: 1,
            operation: 'flows.list',
            flows: { items: [], next: '', skipped: 0 },
        });
        await after;
    });
    it('rejects source work on channel loss and requires a new explicit action instead of reconnecting', async () => {
        const { access, socket, transport, factory } = fixture();
        socket.ready();
        const pending = access.openRecordingSource('default');
        await Promise.resolve();
        await Promise.resolve();
        socket.json({
            type: 'response',
            requestId: '1',
            status: 200,
            contentType: recordingSourceMediaType,
        });
        socket.json({ type: 'source-start', requestId: '1', source: 'default', total: 1 });
        const stream = await pending;
        const next = stream.next();
        const observed = expect(next).rejects.toMatchObject({ code: 'denied' });
        await Promise.resolve();
        socket.onclose?.(new CloseEvent('close'));
        await observed;
        await stream.closed;
        await expect(access.openRecordingSource('default')).rejects.toMatchObject({
            code: 'denied',
        });
        expect(transport).not.toHaveBeenCalled();
        expect(factory).toHaveBeenCalledOnce();
    });
    it('publishes a final filtered total only with its own completed page, not with a provisional progress frame', async () => {
        const { access, socket } = fixture();
        socket.ready();
        let published: unknown;
        const pending = access.managementAuditlogs().then((value) => {
            published = value;
            return value;
        });
        await Promise.resolve();
        await Promise.resolve();
        socket.json({
            type: 'progress',
            requestId: '1',
            phase: 'finalizing',
            completed: 1,
            total: 1,
        });
        await Promise.resolve();
        expect(published).toBeUndefined();
        socket.json({
            type: 'response',
            requestId: '1',
            status: 200,
            contentType: 'application/json; charset=utf-8',
        });
        socket.output(
            '1',
            new TextEncoder().encode(
                JSON.stringify({
                    version: 1,
                    operation: 'auditlogs.list',
                    auditlogs: {
                        items: [
                            {
                                name: 'default',
                                enabled: true,
                                recordingEnabled: true,
                                encrypted: false,
                            },
                        ],
                        next: '',
                        skipped: 0,
                    },
                }),
            ),
        );
        await Promise.resolve();
        expect(published).toBeUndefined();
        socket.json({ type: 'complete', requestId: '1' });
        await expect(pending).resolves.toMatchObject({ total: 1, items: [{ name: 'default' }] });
    });
    it('rejects a completed total that contradicts its page rather than manufacturing a successful empty grid', async () => {
        const { access, socket } = fixture();
        socket.ready();
        const pending = access.managementAuditlogs();
        const observed = expect(pending).rejects.toMatchObject({ code: 'unavailable' });
        await Promise.resolve();
        await Promise.resolve();
        socket.json({
            type: 'progress',
            requestId: '1',
            phase: 'finalizing',
            completed: 0,
            total: 0,
        });
        socket.response('1', {
            version: 1,
            operation: 'auditlogs.list',
            auditlogs: {
                items: [
                    { name: 'default', enabled: true, recordingEnabled: true, encrypted: false },
                ],
                next: '',
                skipped: 0,
            },
        });
        await observed;
    });
    it.each(['management/recordings/list', 'management/auditlogs/list'])(
        'keeps %s alive beyond old deadlines and publishes only its completed result',
        async (action) => {
            const { socket, connection, transport, factory } = fixture();
            socket.ready();
            const progress = vi.fn();
            let settled = false;
            const pending = connection.post(action, {}, 200, undefined, progress).then((value) => {
                settled = true;
                return value;
            });
            await Promise.resolve();
            await vi.advanceTimersByTimeAsync(120_001);
            expect(settled).toBe(false);
            expect(connection.connected()).toBe(true);
            expect(socket.sent.filter((frame) => frame.type === 'cancel')).toHaveLength(0);
            socket.json({
                type: 'progress',
                requestId: '1',
                phase: 'verifying',
                completed: 230,
                total: 284,
            });
            expect(progress).toHaveBeenCalledExactlyOnceWith({
                phase: 'verifying',
                completed: 230,
                total: 284,
            });
            await vi.advanceTimersByTimeAsync(120_001);
            expect(settled).toBe(false);
            expect(socket.sent.filter((frame) => frame.type === 'request')).toHaveLength(1);
            socket.json({
                type: 'response',
                requestId: '1',
                status: 200,
                contentType: 'application/json; charset=utf-8',
            });
            socket.output('1', new TextEncoder().encode('{"safe":true}'));
            await Promise.resolve();
            expect(settled).toBe(false);
            socket.json({ type: 'complete', requestId: '1' });
            await expect(pending).resolves.toEqual({ safe: true });
            expect(factory).toHaveBeenCalledOnce();
            expect(transport).not.toHaveBeenCalled();
        },
    );
    it('cancels a long scan, ignores its late progress and bytes, and preserves admission after the matching acknowledgement', async () => {
        const { socket, connection } = fixture();
        socket.ready();
        const controller = new AbortController();
        const progress = vi.fn();
        const pending = connection.post(
            'management/recordings/list',
            {},
            200,
            controller.signal,
            progress,
        );
        const observed = expect(pending).rejects.toMatchObject({ code: 'cancelled' });
        await Promise.resolve();
        await vi.advanceTimersByTimeAsync(120_001);
        controller.abort();
        await observed;
        socket.json({
            type: 'progress',
            requestId: '1',
            phase: 'verifying',
            completed: 1,
            total: 2,
        });
        expect(progress).not.toHaveBeenCalled();
        socket.json({
            type: 'response',
            requestId: '1',
            status: 200,
            contentType: 'application/json; charset=utf-8',
        });
        socket.output('1', new TextEncoder().encode('ignored'));
        socket.json({ type: 'canceled', requestId: '1' });
        await vi.advanceTimersByTimeAsync(5001);
        expect(connection.connected()).toBe(true);
        const next = connection.post('management/auditlogs/list', {}, 200);
        await Promise.resolve();
        socket.response('2', { current: true });
        await expect(next).resolves.toEqual({ current: true });
    });
    it('bounds missing cancellation acknowledgement independently of an unbounded scan lifetime', async () => {
        const { socket, connection } = fixture();
        socket.ready();
        const controller = new AbortController();
        const pending = connection.post('management/auditlogs/list', {}, 200, controller.signal);
        const observed = expect(pending).rejects.toMatchObject({ code: 'cancelled' });
        await Promise.resolve();
        await vi.advanceTimersByTimeAsync(120_001);
        expect(connection.connected()).toBe(true);
        controller.abort();
        await observed;
        await vi.advanceTimersByTimeAsync(4999);
        expect(connection.connected()).toBe(true);
        await vi.advanceTimersByTimeAsync(1);
        expect(connection.state()).toEqual({ phase: 'interrupted', reason: 'timeout' });
    });
    it.each([
        'uncorrelated',
        'private-field',
        'bad-count',
        'wrong-action',
        'after-response',
        'local-claim',
    ])('fails closed on %s progress without exposing a result', async (mode) => {
        const { socket, connection } = fixture();
        socket.ready();
        const progress = vi.fn();
        const pending = connection.post(
            mode === 'wrong-action' ? 'management/flows/list' : 'management/recordings/list',
            {},
            200,
            undefined,
            progress,
        );
        const observed = expect(pending).rejects.toMatchObject({ code: 'denied' });
        await Promise.resolve();
        if (mode === 'after-response') {
            socket.json({
                type: 'response',
                requestId: '1',
                status: 200,
                contentType: 'application/json; charset=utf-8',
            });
        }
        socket.json({
            type: 'progress',
            requestId: mode === 'uncorrelated' ? '2' : '1',
            phase: mode === 'local-claim' ? 'decrypting' : 'verifying',
            completed: mode === 'bad-count' ? 3 : 1,
            total: 2,
            ...(mode === 'private-field' ? { body: 'must-not-escape' } : {}),
        });
        await observed;
        expect(progress).not.toHaveBeenCalled();
        expect(connection.connected()).toBe(false);
    });
    it('reports catalog warmup only for its completed correlated read and never retries or falls back', async () => {
        const { socket, connection, transport } = fixture();
        socket.ready();
        const pending = connection.post('management/recordings/list', { auditlog: 'default' }, 200);
        await Promise.resolve();
        socket.response(
            '1',
            {
                code: 'recording-catalog-incomplete',
                error: 'recording catalog verification incomplete; refresh to continue',
            },
            503,
        );
        await expect(pending).rejects.toMatchObject({ code: 'catalog-incomplete' });
        await vi.advanceTimersByTimeAsync(1001);
        expect(socket.sent.filter((value) => value.type === 'request')).toHaveLength(1);
        expect(transport).not.toHaveBeenCalled();
        expect(connection.connected()).toBe(true);
    });
    it('never exposes an arbitrary 503 body as a public catalog diagnostic', async () => {
        const { socket, connection } = fixture();
        socket.ready();
        const pending = connection.post('management/recordings/list', { auditlog: 'default' }, 200);
        await Promise.resolve();
        socket.response(
            '1',
            { code: 'recording-catalog-incomplete', error: 'PRIVATE-KEY-OR-PATH' },
            503,
        );
        await expect(pending).rejects.toMatchObject({
            code: 'unavailable',
            message: 'Browser RememberMe: unavailable',
        });
    });
    it('rejects the still-owned operation and unblocks cleanup when response assembly throws', async () => {
        const { socket, connection } = fixture();
        socket.ready();
        const pending = connection.post('management/flows/list', {}, 200);
        await Promise.resolve();
        vi.spyOn(ManagementResponseBuffer.prototype, 'assemble').mockImplementation(() => {
            throw new Error('simulated image assembly failure');
        });
        socket.response('1', { safe: true });
        await expect(pending).rejects.toMatchObject({ code: 'denied' });
        expect(connection.state()).toEqual({ phase: 'interrupted', reason: 'protocol' });
    });
    it('does not fall back to standalone HTTP when constructing its one channel fails', async () => {
        const scope = { origin: 'https://app.example.org', slug: 'Work' };
        const transport = vi.fn();
        const access = new WebAccess(
            new Http(scope, transport),
            {
                scope,
                principal: 'alice',
                environment: 'management',
                terminalAvailable: false,
                expiresAt: new Date(Date.now() + 1000).toISOString(),
                accessToken: `bwa1.${'A'.repeat(43)}`,
            },
            null,
        );
        expect(() =>
            access.openManagement(
                () => {},
                {},
                () => {
                    throw new Error('socket unavailable');
                },
            ),
        ).toThrow();
        expect(access.managementStatus()).toBe('closed');
        await expect(access.managementFlows()).rejects.toMatchObject({ code: 'denied' });
        expect(transport).not.toHaveBeenCalled();
    });
    it('uses the bearer only in open, and keeps an admitted channel usable without renewing that bearer', async () => {
        const { access, socket, transport, factory, token } = fixture();
        const original = access.snapshot().expiresAt;
        socket.ready();
        expect(factory).toHaveBeenCalledWith(
            'wss://app.example.org:8443/api/v1/management/channel',
            'bifroest-management.v1',
        );
        expect(socket.sent[0]).toEqual({
            type: 'open',
            slug: 'Work',
            accessToken: token,
            progress: 'counts-v1',
        });
        vi.advanceTimersByTime(1001);
        expect(access.status()).toBe('expired');
        expect(access.managementStatus()).toBe('active');
        expect(() => access.managementToken()).toThrow();
        expect(() => access.terminalToken()).toThrow();
        const read = access.managementVersion(false);
        await Promise.resolve();
        await Promise.resolve();
        const request = socket.sent.at(-1);
        expect(request).toMatchObject({
            type: 'request',
            action: 'management/version/show',
            fields: { long: 'false' },
        });
        expect(JSON.stringify(request)).not.toContain(token);
        socket.response(String(request?.requestId), {
            version: 1,
            operation: 'version.show',
            versionInfo: { detail: 'short', text: 'fixture' },
        });
        await expect(read).resolves.toEqual({ detail: 'short', text: 'fixture' });
        expect(access.snapshot().expiresAt).toBe(original);
        expect(transport).not.toHaveBeenCalled();
        expect(factory).toHaveBeenCalledOnce();
    });
    it('does not accept a body until a correlated response, nor publish it before completion', async () => {
        const { socket, connection } = fixture();
        socket.ready();
        let done = false;
        const pending = connection.post('management/flows/list', {}, 200).then((value) => {
            done = true;
            return value;
        });
        await Promise.resolve();
        socket.json({
            type: 'response',
            requestId: '1',
            status: 200,
            contentType: 'application/json; charset=utf-8',
        });
        socket.output('1', new TextEncoder().encode('{"safe":true}'));
        await Promise.resolve();
        expect(done).toBe(false);
        socket.json({ type: 'complete', requestId: '1' });
        await expect(pending).resolves.toEqual({ safe: true });
    });
    it('never falls back to HTTP, reconnects, or retries an operation after channel loss', async () => {
        const { access, socket, transport, factory } = fixture();
        socket.ready();
        const pending = access.managementFlows();
        await Promise.resolve();
        await Promise.resolve();
        socket.onclose?.(new CloseEvent('close'));
        await expect(pending).rejects.toMatchObject({ code: 'denied' });
        await expect(access.managementFlows()).rejects.toMatchObject({ code: 'denied' });
        expect(() => access.openManagement(() => {})).toThrow();
        expect(transport).not.toHaveBeenCalled();
        expect(factory).toHaveBeenCalledOnce();
        expect(access.status()).toBe('active');
        expect(access.managementStatus()).toBe('closed');
    });
    it('cancels just its own read and drains late bytes without turning them into a different response', async () => {
        const { connection, socket } = fixture();
        socket.ready();
        const abort = new AbortController();
        const pending = connection.post('management/flows/list', {}, 200, abort.signal);
        await Promise.resolve();
        socket.json({
            type: 'response',
            requestId: '1',
            status: 200,
            contentType: 'application/json; charset=utf-8',
        });
        abort.abort();
        await expect(pending).rejects.toMatchObject({ code: 'cancelled' });
        expect(socket.sent.at(-1)).toEqual({ type: 'cancel', requestId: '1' });
        socket.output('1', new TextEncoder().encode('ignored'));
        socket.json({ type: 'canceled', requestId: '1' });
        expect(connection.connected()).toBe(true);
        const next = connection.post('management/flows/list', {}, 200);
        await Promise.resolve();
        socket.response('2', { current: true });
        await expect(next).resolves.toEqual({ current: true });
    });
    it('changes settings only after a matching acknowledgement without creating another connection', async () => {
        const { connection, socket, factory } = fixture();
        socket.ready();
        const pending = connection.setKeepAlive('10s');
        await Promise.resolve();
        expect(connection.keepAliveSettings().interval).toBe('15s');
        socket.json({
            type: 'keepalive',
            requestId: '1',
            keepAlive: { interval: '10s', locked: false },
        });
        await expect(pending).resolves.toEqual({ interval: '10s', locked: false });
        expect(factory).toHaveBeenCalledOnce();
    });
    it.each(['unknown', 'unsolicited', 'binary-before-header'])(
        'fails closed on %s data without success',
        async (mode) => {
            const { connection, socket } = fixture();
            socket.ready();
            const pending = connection.post('management/flows/list', {}, 200);
            await Promise.resolve();
            if (mode === 'unknown') {
                socket.json({ type: 'exit', status: 0 });
            } else if (mode === 'unsolicited') {
                socket.json({ type: 'complete', requestId: '2' });
            } else {
                socket.output('1', new Uint8Array([1]));
            }
            await expect(pending).rejects.toMatchObject({ code: 'denied' });
            expect(connection.connected()).toBe(false);
        },
    );
});
