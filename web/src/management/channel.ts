import {
  type ArtifactRequest,
  artifactFields,
  maximumTransferImageBytes,
  transferMediaType,
} from '../artifacts/protocol';
import type { AccessSnapshot } from '../remember/client';
import { type ArtifactResponseImage, object } from '../remember/http';
import { RememberMeError } from '../remember/protocol';
import {
  defaultKeepAlive,
  type KeepAlivePolicy,
  keepAliveDuration,
  keepAlivePolicy,
} from '../terminal/keepalive';
import type { Socket, SocketFactory, TerminalState } from '../terminal/socket';
import { ManagementResponseBuffer } from './response-buffer';

const protocol = 'bifroest-management.v1';
const allowed = new Set([
  'management/flows/list',
  'management/version/show',
  'management/sessions/list',
  'management/sessions/show',
  'management/auditlogs/list',
  'management/recordings/list',
  'management/sessions/prepare',
  'management/sessions/confirm',
  'management/sessions/cancel',
  'management/artifacts/recording',
  'management/artifacts/audit',
]);
interface Pending {
  status: number | null;
  media: string;
  buffer: ManagementResponseBuffer;
  length: number;
  maximum: number;
  expected: number;
  resolve(value: ArtifactResponseImage): void;
  reject(error: RememberMeError): void;
  retire(): void;
  aborted: boolean;
}

// One pre-expiry admission, owned by one management tab. No reconnect, bearer
// renewal, persistence, shell execution or fallback to a different actor.
export class ManagementConnection {
  readonly #socket: Socket;
  readonly #pending = new Map<string, Pending>();
  readonly #ready: Promise<void>;
  #resolveReady!: () => void;
  #rejectReady!: (error: RememberMeError) => void;
  #state: TerminalState = { phase: 'connecting' };
  #sequence = 0;
  #policy: KeepAlivePolicy;
  #settings: {
    id: string;
    resolve(value: KeepAlivePolicy): void;
    reject(error: RememberMeError): void;
    timer: ReturnType<typeof setTimeout>;
  } | null = null;
  #openTimer: ReturnType<typeof setTimeout>;
  #proof: (() => string) | null;
  readonly #changed: (state: TerminalState) => void;

  constructor(
    access: { snapshot(): AccessSnapshot; managementToken(): string },
    changed: (state: TerminalState) => void,
    factory: SocketFactory = (url, selected) => {
      const check = new URL(url);
      check.protocol = 'https:';
      if (check.origin !== location.origin) {
        throw new Error('foreign management origin');
      }
      return new WebSocket(url, selected);
    },
    options: { keepAlive?: string } = {},
  ) {
    const snapshot = access.snapshot();
    if (snapshot.environment !== 'management') {
      throw new RememberMeError('denied');
    }
    this.#changed = changed;
    this.#policy = snapshot.keepAlive ?? defaultKeepAlive;
    this.#proof = () => access.managementToken();
    this.#ready = new Promise((resolve, reject) => {
      this.#resolveReady = resolve;
      this.#rejectReady = reject;
    });
    void this.#ready.catch(() => {});
    const url = new URL('/_bifroest/api/v1/management/channel', snapshot.scope.origin);
    url.protocol = 'wss:';
    this.#socket = factory(url.href, protocol);
    this.#socket.binaryType = 'arraybuffer';
    this.#openTimer = setTimeout(() => this.#stop('timeout'), 5000);
    this.#socket.onopen = () => {
      const proof = this.#proof;
      this.#proof = null;
      if (this.#state.phase !== 'connecting') {
        return;
      }
      try {
        if (this.#socket.protocol !== protocol || proof === null) {
          throw new Error();
        }
        const preference =
          !this.#policy.locked && keepAliveDuration(options.keepAlive) !== null
            ? options.keepAlive
            : undefined;
        this.#socket.send(
          JSON.stringify({
            type: 'open',
            slug: snapshot.scope.slug,
            accessToken: proof(),
            ...(preference === undefined ? {} : { keepAlive: preference }),
          }),
        );
      } catch {
        this.#stop('access-required');
      }
    };
    this.#socket.onmessage = (event) => {
      try {
        this.#message(event.data as unknown);
      } catch {
        this.#stop('protocol');
      }
    };
    this.#socket.onerror = () => this.#stop('connection-lost');
    this.#socket.onclose = () => this.#stop('connection-lost');
  }
  state(): TerminalState {
    return this.#state;
  }
  connected(): boolean {
    return this.#state.phase === 'connected';
  }
  available(): boolean {
    return this.#state.phase === 'connecting' || this.connected();
  }
  keepAliveSettings = (): KeepAlivePolicy => this.#policy;
  disconnect = (): void => this.#stop();
  async setKeepAlive(interval: string): Promise<KeepAlivePolicy> {
    await this.#ready;
    if (!this.connected() || this.#policy.locked || keepAliveDuration(interval) === null) {
      throw new RememberMeError('denied');
    }
    if (this.#settings !== null) {
      throw new RememberMeError('busy');
    }
    return new Promise((resolve, reject) => {
      const id = String(++this.#sequence);
      const timer = setTimeout(() => this.#stop('timeout'), 5000);
      this.#settings = { id, resolve, reject, timer };
      this.#send({ type: 'keepalive', requestId: id, interval });
    });
  }
  async post(
    action: string,
    fields: Record<string, string>,
    expected: number,
    signal?: AbortSignal,
  ): Promise<unknown> {
    const result = await this.#request(action, fields, expected, 64 << 10, signal);
    try {
      if (expected === 204) {
        if (result.bytes.byteLength !== 0) {
          throw new Error();
        }
        return undefined;
      }
      if (result.mediaType !== 'application/json; charset=utf-8') {
        throw new Error();
      }
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result.bytes)) as unknown;
    } catch {
      throw new RememberMeError('unavailable');
    } finally {
      new Uint8Array(result.bytes).fill(0);
    }
  }
  async artifactImage(
    request: ArtifactRequest,
    signal: AbortSignal,
  ): Promise<ArtifactResponseImage> {
    const result = await this.#request(
      `management/artifacts/${request.kind}`,
      artifactFields(request),
      200,
      maximumTransferImageBytes,
      signal,
    );
    if (result.mediaType !== transferMediaType) {
      new Uint8Array(result.bytes).fill(0);
      throw new RememberMeError('unavailable');
    }
    return result;
  }
  async #request(
    action: string,
    fields: Record<string, string>,
    expected: number,
    maximum: number,
    signal?: AbortSignal,
  ): Promise<ArtifactResponseImage> {
    if (!allowed.has(action) || 'slug' in fields) {
      throw new RememberMeError('unavailable');
    }
    if (signal?.aborted) {
      throw new RememberMeError('cancelled');
    }
    await this.#ready;
    if (signal?.aborted) {
      throw new RememberMeError('cancelled');
    }
    if (!this.connected()) {
      throw new RememberMeError('denied');
    }
    if (this.#pending.size >= 4) {
      throw new RememberMeError('busy');
    }
    const id = String(++this.#sequence);
    return new Promise((resolve, reject) => {
      const abort = () => {
        const entry = this.#pending.get(id);
        if (!entry || entry.aborted) {
          return;
        }
        entry.aborted = true;
        entry.buffer.wipe();
        reject(new RememberMeError(signal?.aborted ? 'cancelled' : 'unavailable'));
        this.#send({ type: 'cancel', requestId: id });
      };
      const timer = setTimeout(abort, 20000);
      const retired = setTimeout(() => {
        if (this.#pending.has(id)) {
          this.#stop('timeout');
        }
      }, 25000);
      this.#pending.set(id, {
        status: null,
        media: '',
        buffer: new ManagementResponseBuffer(maximum),
        length: 0,
        maximum,
        expected,
        resolve,
        reject,
        aborted: false,
        retire: () => {
          clearTimeout(timer);
          clearTimeout(retired);
          signal?.removeEventListener('abort', abort);
        },
      });
      signal?.addEventListener('abort', abort, { once: true });
      this.#send({ type: 'request', requestId: id, action, fields });
      if (signal?.aborted) {
        abort();
      }
    });
  }
  #send(value: unknown): void {
    try {
      const encoded = JSON.stringify(value);
      if (
        new TextEncoder().encode(encoded).byteLength > 16 << 10 ||
        this.#socket.bufferedAmount > 64 << 10
      ) {
        throw new Error();
      }
      this.#socket.send(encoded);
    } catch {
      this.#stop('input-limit');
    }
  }
  #message(data: unknown): void {
    if (!this.available()) {
      return;
    }
    if (data instanceof ArrayBuffer) {
      if (!this.connected() || data.byteLength < 9 || data.byteLength > 16 << 10) {
        throw new Error();
      }
      const id = new DataView(data).getBigUint64(0);
      if (id > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error();
      }
      const entry = this.#pending.get(String(id));
      if (!entry || entry.status === null) {
        throw new Error();
      }
      entry.length += data.byteLength - 8;
      if (entry.length > entry.maximum) {
        throw new Error();
      }
      if (!entry.aborted) {
        entry.buffer.append(new Uint8Array(data, 8));
      }
      return;
    }
    if (typeof data !== 'string' || new TextEncoder().encode(data).byteLength > 4096) {
      throw new Error();
    }
    const decoded = JSON.parse(data) as Record<string, unknown>;
    if (decoded?.type === 'ready') {
      const value = object(decoded, ['type', 'connectionId', 'keepAlive']);
      if (
        this.#state.phase !== 'connecting' ||
        typeof value.connectionId !== 'string' ||
        !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(value.connectionId)
      ) {
        throw new Error();
      }
      this.#policy = keepAlivePolicy(value.keepAlive) ?? defaultKeepAlive;
      clearTimeout(this.#openTimer);
      this.#state = { phase: 'connected' };
      this.#resolveReady();
      this.#changed(this.#state);
      return;
    }
    if (!this.connected()) {
      throw new Error();
    }
    if (decoded?.type === 'keepalive') {
      const value = object(decoded, ['type', 'requestId', 'keepAlive']);
      const settings = this.#settings;
      if (!settings || value.requestId !== settings.id) {
        throw new Error();
      }
      this.#policy = keepAlivePolicy(value.keepAlive) ?? defaultKeepAlive;
      clearTimeout(settings.timer);
      this.#settings = null;
      settings.resolve(this.#policy);
      return;
    }
    if (
      !['response', 'complete', 'canceled'].includes(String(decoded?.type)) ||
      typeof decoded.requestId !== 'string'
    ) {
      throw new Error();
    }
    const entry = this.#pending.get(decoded.requestId);
    if (!entry) {
      throw new Error();
    }
    if (decoded.type === 'response') {
      const value = object(decoded, ['type', 'requestId', 'status', 'contentType']);
      if (
        entry.status !== null ||
        !Number.isInteger(value.status) ||
        Number(value.status) < 200 ||
        Number(value.status) > 599 ||
        typeof value.contentType !== 'string'
      ) {
        throw new Error();
      }
      entry.status = Number(value.status);
      entry.media = value.contentType;
      return;
    }
    object(decoded, ['type', 'requestId']);
    if (
      decoded.type === 'canceled' ||
      entry.status === null ||
      entry.status !== entry.expected ||
      entry.aborted
    ) {
      this.#pending.delete(decoded.requestId);
      entry.retire();
      entry.buffer.wipe();
      entry.reject(
        new RememberMeError(
          decoded.type === 'canceled'
            ? 'cancelled'
            : entry.status === 401 || entry.status === 403
              ? 'denied'
              : entry.status === 429
                ? 'rate-limited'
                : 'unavailable',
        ),
      );
      return;
    }
    // Keep this entry reachable until allocation/copy has succeeded. The outer
    // protocol failure path must still reject it and unblock awaiting cleanup.
    const result = entry.buffer.assemble();
    this.#pending.delete(decoded.requestId);
    entry.retire();
    entry.resolve({ bytes: result, mediaType: entry.media, status: entry.status });
  }
  #stop(
    reason?: 'timeout' | 'protocol' | 'connection-lost' | 'input-limit' | 'access-required',
  ): void {
    if (!this.available()) {
      return;
    }
    this.#state = reason ? { phase: 'interrupted', reason } : { phase: 'disconnected' };
    this.#proof = null;
    clearTimeout(this.#openTimer);
    const failure = new RememberMeError('denied');
    this.#rejectReady(failure);
    for (const entry of this.#pending.values()) {
      entry.retire();
      entry.buffer.wipe();
      entry.reject(failure);
    }
    this.#pending.clear();
    if (this.#settings) {
      clearTimeout(this.#settings.timer);
      this.#settings.reject(failure);
      this.#settings = null;
    }
    this.#socket.onopen = null;
    this.#socket.onmessage = null;
    this.#socket.onerror = null;
    this.#socket.onclose = null;
    try {
      this.#socket.close();
    } finally {
      this.#changed(this.#state);
    }
  }
}
