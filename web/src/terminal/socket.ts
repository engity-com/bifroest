import { object } from '../remember/http';
import type { AccessSnapshot } from '../remember';

export type TerminalFailure = 'protocol' | 'connection-lost' | 'server-error' | 'input-limit' | 'output-limit' | 'timeout' | 'access-required' | 'configuration';
export type TerminalState =
  | { readonly phase: 'connecting' }
  | { readonly phase: 'connected' }
  | { readonly phase: 'finishing' }
  | { readonly phase: 'exited'; readonly status: number }
  | { readonly phase: 'interrupted'; readonly reason: TerminalFailure }
  | { readonly phase: 'disconnected' };
export interface TerminalAccess { snapshot(): AccessSnapshot; terminalToken(): string; }
export interface Task { readonly kind: 'shell' | 'exec'; readonly command: string; readonly pty: boolean; readonly columns: number; readonly rows: number; }
export interface Renderer { write(channel: 0 | 1, data: Uint8Array, done: () => void): void; }
export interface Socket {
  binaryType: BinaryType; readonly protocol: string; readonly readyState: number; readonly bufferedAmount: number;
  onopen: ((event: Event) => void) | null; onmessage: ((event: MessageEvent) => void) | null;
  onerror: ((event: Event) => void) | null; onclose: ((event: CloseEvent) => void) | null;
  send(data: string | Uint8Array<ArrayBuffer>): void; close(code?: number, reason?: string): void;
}
export type SocketFactory = (url: string, protocol: string) => Socket;

const protocol = 'bifroest-terminal.v1';
const maxMessage = 16 << 10;
const maxInput = 64 << 10;
const maxOutput = 256 << 10;
const uuid = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;
const encoder = new TextEncoder();

function nativeSocket(url: string, selected: string): Socket {
  const parsed = new URL(url); parsed.protocol = 'https:';
  if (parsed.origin !== location.origin) throw new Error('foreign terminal origin');
  return new WebSocket(url, selected);
}
function dimensions(columns: number, rows: number): boolean {
  return Number.isInteger(columns) && Number.isInteger(rows) && columns > 0 && columns <= 65535 && rows > 0 && rows <= 65535;
}

// One owned connection == one fresh execution. No reconnect, storage, raw server
// diagnostics, URL/subprotocol proof or successful-close-without-exit fallback.
export class TerminalConnection {
  readonly #socket: Socket;
  readonly #renderer: Renderer;
  readonly #onState: (state: TerminalState) => void;
  #state: TerminalState = { phase: 'connecting' };
  #proof: (() => string) | null;
  #ready = false;
  #inputClosed = false;
  #stopped = false;
  #final: TerminalState | null = null;
  #output: { channel: 0 | 1; bytes: Uint8Array<ArrayBuffer> }[] = [];
  #outputBytes = 0;
  #writing = false;
  #outputTimer: ReturnType<typeof setTimeout> | undefined;
  #openTimer: ReturnType<typeof setTimeout> | undefined;
  #sender: ReturnType<typeof setInterval> | undefined;
  #sendQueue: (Uint8Array<ArrayBuffer> | string)[] = [];
  #sendBytes = 0;
  #controls = 0;
  #lastData = -Infinity;
  #lastDataSize = 0;
  #lastControl = -Infinity;
  #blockedSince = 0;
  readonly #pty: boolean;

  constructor(access: TerminalAccess, task: Task, renderer: Renderer, onState: (state: TerminalState) => void, factory: SocketFactory = nativeSocket) {
    const scope = access.snapshot().scope;
    if (!access.snapshot().terminalAvailable || !dimensions(task.columns, task.rows) ||
        (task.kind !== 'shell' && task.kind !== 'exec') || !task.command.isWellFormed() ||
        encoder.encode(task.command).byteLength > 4096 || task.command.includes('\0')) throw new Error('terminal configuration unavailable');
    this.#renderer = renderer; this.#onState = onState; this.#pty = task.pty;
    const url = new URL('/_bifroest/api/v1/terminal', scope.origin); url.protocol = 'wss:';
    this.#proof = () => access.terminalToken();
    this.#socket = factory(url.href, protocol);
    this.#socket.binaryType = 'arraybuffer';
    this.#socket.onopen = () => {
      if (this.#stopped) return;
      if (this.#socket.protocol !== protocol) { this.#fail('protocol'); return; }
      const proof = this.#proof; this.#proof = null;
      try {
        if (proof === null) throw new Error();
        this.#socket.send(JSON.stringify({ type: 'open', slug: scope.slug, accessToken: proof(), task: task.kind,
          ...(task.kind === 'exec' ? { command: task.command } : {}),
          ...(task.pty ? { pty: { term: 'xterm-256color', columns: task.columns, rows: task.rows } } : {}),
        }));
      } catch { this.#fail('access-required'); }
    };
    this.#socket.onmessage = event => this.#message(event.data as unknown);
    this.#socket.onerror = () => { if (this.#final?.phase !== 'exited') this.#fail('connection-lost'); };
    this.#socket.onclose = () => {
      this.#stopSending();
      if (this.#final === null) this.#finish({ phase: 'interrupted', reason: 'connection-lost' });
    };
    this.#openTimer = setTimeout(() => this.#fail('timeout'), 20_000);
    this.#sender = setInterval(() => this.#flush(), 20);
  }

  state(): TerminalState { return this.#state; }

  input(value: Uint8Array): boolean {
    if (!this.#ready || this.#inputClosed || this.#stopped) return false;
    if (value.byteLength > maxInput - this.#sendBytes) { this.#fail('input-limit'); return false; }
    for (let offset = 0; offset < value.byteLength; offset += 4096) this.#sendQueue.push(value.slice(offset, offset + 4096));
    this.#sendBytes += value.byteLength;
    this.#flush(); return true;
  }

  resize(columns: number, rows: number): boolean {
    if (!this.#pty || !dimensions(columns, rows)) return false;
    // Coalesce only unsent resizes; input/EOF/signal ordering is never changed.
    const last = this.#sendQueue[this.#sendQueue.length - 1];
    if (typeof last === 'string' && last.startsWith('{"type":"resize"')) {
      this.#sendQueue[this.#sendQueue.length - 1] = JSON.stringify({ type: 'resize', columns, rows }); return true;
    }
    return this.#control({ type: 'resize', columns, rows });
  }
  signal(signal: 'INT' | 'TERM'): boolean {
    if (signal !== 'INT' && signal !== 'TERM') return false;
    return this.#control({ type: 'signal', signal });
  }
  eof(): boolean {
    if (this.#inputClosed) return false;
    if (!this.#control({ type: 'eof' })) return false;
    this.#inputClosed = true; return true;
  }

  disconnect(): void {
    if (this.#final !== null) return;
    this.#finish({ phase: 'disconnected' });
    this.#close();
  }
  dispose(): void {
    this.#stopSending(); this.#stopped = true; this.#proof = null;
    clearTimeout(this.#outputTimer);
    this.#output = []; this.#outputBytes = 0; this.#writing = false;
    this.#socket.onopen = this.#socket.onmessage = this.#socket.onerror = this.#socket.onclose = null;
    this.#close();
  }

  #control(value: object): boolean {
    if (!this.#ready || this.#stopped) return false;
    if (this.#controls >= 16) { this.#fail('input-limit'); return false; }
    this.#sendQueue.push(JSON.stringify(value)); this.#controls++; this.#flush(); return true;
  }
  #flush(): void {
    if (!this.#ready || this.#stopped || this.#socket.readyState !== 1 || this.#sendQueue.length === 0) return;
    const now = performance.now();
    if (this.#socket.bufferedAmount > 32 << 10) {
      if (this.#blockedSince === 0) this.#blockedSince = now;
      else if (now - this.#blockedSince > 5000) this.#fail('input-limit');
      return;
    }
    this.#blockedSince = 0;
    const next = this.#sendQueue[0]!;
    if (typeof next === 'string' ? now - this.#lastControl < 100 : now - this.#lastData < Math.max(22, this.#lastDataSize / 40960 * 1000)) return;
    this.#sendQueue.shift();
    if (typeof next === 'string') { this.#lastControl = now; this.#controls--; }
    else { this.#lastData = now; this.#lastDataSize = next.byteLength; this.#sendBytes -= next.byteLength; }
    try { this.#socket.send(next); } catch { this.#fail('connection-lost'); }
  }

  #message(value: unknown): void {
    if (this.#final !== null) {
      if (this.#final.phase === 'exited') this.#fail('protocol');
      return;
    }
    try {
      if (value instanceof ArrayBuffer) {
        const bytes = new Uint8Array(value);
        if (!this.#ready || bytes.length < 2 || bytes.length > maxMessage || (bytes[0] !== 0 && bytes[0] !== 1)) throw new Error();
        if (this.#outputBytes + bytes.length - 1 > maxOutput || this.#output.length >= 64) { this.#fail('output-limit'); return; }
        this.#output.push({ channel: bytes[0], bytes: bytes.slice(1) }); this.#outputBytes += bytes.length - 1; this.#drain(); return;
      }
      if (typeof value !== 'string' || value.length > 1024) throw new Error();
      const message = JSON.parse(value) as Record<string, unknown>;
      switch (message?.type) {
        case 'ready':
          object(message, ['type', 'connectionId']);
          if (this.#ready || typeof message.connectionId !== 'string' || !uuid.test(message.connectionId)) throw new Error();
          this.#ready = true; clearTimeout(this.#openTimer); this.#publish({ phase: 'connected' }); break;
        case 'exit':
          object(message, ['type', 'status']);
          if (!this.#ready || !Number.isInteger(message.status) || (message.status as number) < 0 || (message.status as number) > 0xffffffff) throw new Error();
          this.#finish({ phase: 'exited', status: message.status as number }); this.#close(); break;
        case 'error':
          object(message, ['type', 'code']);
          if (typeof message.code !== 'string' || !['invalid-open', 'authentication-denied', 'terminal-unavailable', 'connection-denied', 'execution-failed'].includes(message.code)) throw new Error();
          this.#fail('server-error'); break;
        default: throw new Error();
      }
    } catch { this.#fail('protocol'); }
  }

  #drain(): void {
    if (this.#writing) return;
    const next = this.#output[0];
    if (next === undefined) { if (this.#final !== null) this.#publish(this.#final); return; }
    this.#writing = true;
    let completed = false;
    this.#outputTimer = setTimeout(() => { if (!completed) this.#fail('output-limit'); }, 5000);
    try {
      this.#renderer.write(next.channel, next.bytes, () => {
        if (completed || !this.#writing) return;
        completed = true; clearTimeout(this.#outputTimer);
        this.#output.shift(); this.#outputBytes -= next.bytes.byteLength; this.#writing = false; this.#drain();
      });
    } catch { this.#fail('output-limit'); }
  }
  #stopSending(): void {
    clearTimeout(this.#openTimer); clearInterval(this.#sender);
    this.#proof = null; this.#stopped = true; this.#ready = false;
    this.#sendQueue = []; this.#sendBytes = 0; this.#controls = 0;
  }
  #finish(state: TerminalState): void {
    this.#stopSending(); this.#final = state;
    if (this.#writing || this.#output.length > 0) this.#publish({ phase: 'finishing' });
    this.#drain();
  }
  #fail(reason: TerminalFailure): void {
    if (this.#final !== null && this.#final.phase !== 'exited') return;
    clearTimeout(this.#outputTimer); this.#writing = false;
    this.#output = []; this.#outputBytes = 0;
    this.#finish({ phase: 'interrupted', reason }); this.#close();
  }
  #publish(state: TerminalState): void { this.#state = Object.freeze({ ...state }); this.#onState(this.#state); }
  #close(): void { try { this.#socket.close(1000, 'terminal closed'); } catch { /* No unbounded close retry. */ } }
}
