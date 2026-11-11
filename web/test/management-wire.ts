import { EventEmitter } from 'node:events';
import type { Response } from 'playwright';
import type { SocketObserverPage } from './fixture-types.ts';

export interface ManagementRequest {
    method(): string;
    url(): string;
    headers(): Record<string, string>;
    postData(): string;
    channel(): string;
    requestId(): string;
    slug(): string;
    transport: string;
}

export interface ManagementResponse {
    contentType(): string;
    url(): string;
    status(): number;
    request(): ManagementRequest;
    json: Response['json'];
    finished: Response['finished'];
}

export interface ManagementProgress {
    request: ManagementRequest;
    phase: string;
    completed: number;
    total: number;
}

export interface SourceEntry {
    request: ManagementRequest;
    recordingId: string;
    index: number;
    total: number;
    size: number;
    encrypted: boolean;
}

interface ManagementEvents {
    request: [ManagementRequest];
    response: [ManagementResponse];
    progress: [ManagementProgress];
    'source-start': [SourceEntry];
    'source-entry': [SourceEntry];
    'source-entry-complete': [SourceEntry];
    'source-failed': [SourceEntry];
}

interface ManagementWire {
    on: EventEmitter<ManagementEvents>['on'];
    off: EventEmitter<ManagementEvents>['off'];
    waitForResponse(
        predicate: (response: ManagementResponse) => boolean,
    ): Promise<ManagementResponse>;
}

const observers = new WeakMap<object, ManagementWire>();

// Observe actual Playwright WebSocket frames, without replacing fetch, socket
// factories, TLS/Origin checks, request payloads or application callbacks. URLs
// below identify logical RPC operations, NOT additional HTTP requests. A wire
// request has no HTTP authorization/cookie headers: actor binding is its admitted
// channel UUID, and scope comes only from that channel's original open frame.
export function managementWire(page: SocketObserverPage): ManagementWire {
    const existing = observers.get(page);
    if (existing) {
        return existing;
    }
    const events = new EventEmitter<ManagementEvents>();
    const wire: ManagementWire = {
        on: (name, listener) => events.on(name, listener),
        off: (name, listener) => events.off(name, listener),
        waitForResponse(predicate) {
            const pending = new Promise<ManagementResponse>((resolve, reject) => {
                const timeout = setTimeout(() => {
                    events.off('response', received);
                    reject(new Error('management-response-timeout'));
                }, 30000);
                const received = (response: ManagementResponse) => {
                    if (predicate(response)) {
                        clearTimeout(timeout);
                        events.off('response', received);
                        resolve(response);
                    }
                };
                events.on('response', received);
            });
            void pending.catch(() => {});
            return pending;
        },
    };
    observers.set(page, wire);
    page.on('websocket', (socket) => {
        const endpoint = new URL(socket.url());
        if (endpoint.pathname !== '/api/v1/management/channel') {
            return;
        }
        endpoint.protocol = 'https:';
        let slug = '';
        let channel = '';
        const pending = new Map<
            string,
            {
                request: ManagementRequest;
                resolve(value: Buffer): void;
                reject(reason: unknown): void;
                body: Promise<Buffer>;
                timer: ReturnType<typeof setTimeout>;
                chunks: Buffer[];
                length: number;
                artifact: boolean;
            }
        >();
        socket.on('framesent', ({ payload }) => {
            if (typeof payload !== 'string') {
                return;
            }
            const value = JSON.parse(payload);
            if (value.type === 'open') {
                slug = value.slug;
                return;
            }
            if (value.type !== 'request') {
                return;
            }
            const url = new URL(`/api/v1/${value.action}`, endpoint.origin).href;
            const request = {
                url: () => url,
                method: () => 'RPC',
                headers: () => ({}),
                postData: () => JSON.stringify(value.fields),
                channel: () => channel,
                requestId: () => value.requestId,
                slug: () => slug,
                transport: 'websocket',
            };
            const { promise: body, resolve, reject } = Promise.withResolvers<Buffer>();
            void body.catch(() => {});
            const timer = setTimeout(() => {
                pending.delete(value.requestId);
                reject(new Error('management-body-timeout'));
            }, 30000);
            pending.set(value.requestId, {
                request,
                resolve,
                reject,
                body,
                timer,
                chunks: [],
                length: 0,
                artifact: value.action.startsWith('management/artifacts/'),
            });
            events.emit('request', request);
        });
        socket.on('framereceived', ({ payload }) => {
            if (typeof payload !== 'string') {
                if (payload.length < 8) {
                    return;
                }
                const entry = pending.get(payload.readBigUInt64BE(0).toString());
                if (!entry || entry.artifact) {
                    return;
                }
                entry.length += payload.length - 8;
                if (entry.length > 64 << 10) {
                    entry.reject(new Error('management-body-limit'));
                    entry.chunks = [];
                    return;
                }
                entry.chunks.push(Buffer.from(payload.subarray(8)));
                return;
            }
            const value = JSON.parse(payload);
            if (value.type === 'ready') {
                channel = value.connectionId;
                return;
            }
            const entry = pending.get(value.requestId);
            if (!entry) {
                return;
            }
            if (value.type === 'response') {
                const response = {
                    contentType: () => value.contentType,
                    url: entry.request.url,
                    status: () => value.status,
                    request: () => entry.request,
                    transport: 'websocket',
                    json: async () => JSON.parse((await entry.body).toString('utf8')),
                    finished: async () => {
                        await entry.body;
                        return null;
                    },
                };
                events.emit('response', response);
            } else if (value.type === 'progress') {
                events.emit('progress', {
                    request: entry.request,
                    phase: value.phase,
                    completed: value.completed,
                    total: value.total,
                });
            } else if (
                ['source-start', 'source-entry', 'source-entry-complete', 'source-failed'].includes(
                    value.type,
                )
            ) {
                events.emit(value.type, { ...value, request: entry.request });
            } else if (value.type === 'complete' || value.type === 'canceled') {
                clearTimeout(entry.timer);
                pending.delete(value.requestId);
                if (value.type === 'canceled') {
                    entry.reject(new Error('management-response-cancelled'));
                } else {
                    entry.resolve(Buffer.concat(entry.chunks));
                }
            }
        });
        socket.on('close', () => {
            for (const entry of pending.values()) {
                clearTimeout(entry.timer);
                entry.reject(new Error('management-channel-closed'));
            }
            pending.clear();
        });
    });
    return wire;
}

export function existingManagementWire(page: object) {
    return observers.get(page);
}
