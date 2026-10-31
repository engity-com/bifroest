import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { noncedDocument } from '../src/terminal/document';
import type { Renderer, Socket, Task, TerminalAccess, TerminalState } from '../src/terminal/socket';
import { TerminalConnection } from '../src/terminal/socket';
import { required } from './required';

const uuid = '70d5159d-a0e4-46ca-b011-c4f831f4ade0';
const proof = `bwa1.${'A'.repeat(43)}`;
const access: TerminalAccess = {
  snapshot: () => ({
    scope: { origin: 'https://app.example.org:8443', slug: 'Work' },
    principal: 'alice',
    environment: 'terminal',
    terminalAvailable: true,
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
  }),
  terminalToken: () => proof,
};

class FakeSocket implements Socket {
  binaryType: BinaryType = 'blob';
  protocol = 'bifroest-terminal.v1';
  readyState = 0;
  bufferedAmount = 0;
  onopen: Socket['onopen'] = null;
  onmessage: Socket['onmessage'] = null;
  onerror: Socket['onerror'] = null;
  onclose: Socket['onclose'] = null;
  sent: (string | Uint8Array)[] = [];
  closes = 0;
  send(data: string | Uint8Array<ArrayBuffer>) {
    this.sent.push(typeof data === 'string' ? data : data.slice());
  }
  close() {
    this.closes++;
    this.serverClose(1000);
  }
  open() {
    this.readyState = 1;
    this.onopen?.(new Event('open'));
  }
  message(data: unknown) {
    this.onmessage?.(new MessageEvent('message', { data }));
  }
  ready() {
    this.message(JSON.stringify({ type: 'ready', connectionId: uuid }));
  }
  output(data: Uint8Array, channel = 0) {
    const message = new Uint8Array(data.length + 1);
    message[0] = channel;
    message.set(data, 1);
    this.message(message.buffer);
  }
  serverClose(code: number) {
    this.readyState = 3;
    this.onclose?.(new CloseEvent('close', { code }));
  }
}

const connections: TerminalConnection[] = [];
function fixture(
  renderer: Renderer = {
    write(_channel, _data, done) {
      done();
    },
  },
  selected = access,
  task: Partial<Task> = {},
) {
  const socket = new FakeSocket();
  const states: TerminalState[] = [];
  let endpoint = '';
  let subprotocol = '';
  const connection = new TerminalConnection(
    selected,
    { kind: 'shell', command: '', pty: true, columns: 80, rows: 24, ...task },
    renderer,
    (state) => states.push(state),
    (url, protocol) => {
      endpoint = url;
      subprotocol = protocol;
      return socket;
    },
  );
  connections.push(connection);
  return { socket, connection, states, endpoint, subprotocol };
}
beforeEach(() =>
  vi.useFakeTimers({
    toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'performance'],
  }),
);
afterEach(() => {
  for (const connection of connections.splice(0)) {
    connection.dispose();
  }
  vi.useRealTimers();
});

describe('owned bounded browser terminal protocol', () => {
  it('puts proof only into the first open frame, never URL or subprotocol', () => {
    const { socket, connection, endpoint, subprotocol } = fixture();
    expect(endpoint).toBe('wss://app.example.org:8443/_bifroest/api/v1/terminal');
    expect(subprotocol).toBe('bifroest-terminal.v1');
    expect(endpoint + subprotocol).not.toContain(proof);
    expect(connection.input(new Uint8Array([65]))).toBe(false);
    expect(socket.sent).toHaveLength(0);
    socket.open();
    expect(socket.binaryType).toBe('arraybuffer');
    expect(socket.sent).toHaveLength(1);
    expect(JSON.parse(socket.sent[0] as string)).toEqual({
      type: 'open',
      slug: 'Work',
      accessToken: proof,
      task: 'shell',
      pty: { term: 'xterm-256color', columns: 80, rows: 24 },
    });
    socket.ready();
    expect(connection.state()).toEqual({ phase: 'connected' });
  });

  it('validates fresh proof at wire open and rejects mismatched negotiated protocol before sending it', () => {
    const expired = fixture(undefined, {
      ...access,
      terminalToken() {
        throw new Error('private auth diagnostic');
      },
    });
    expired.socket.open();
    expect(expired.socket.sent).toHaveLength(0);
    expect(expired.connection.state()).toEqual({ phase: 'interrupted', reason: 'access-required' });
    const wrong = fixture();
    wrong.socket.protocol = 'wrong';
    wrong.socket.open();
    expect(wrong.socket.sent).toHaveLength(0);
    expect(wrong.connection.state()).toEqual({ phase: 'interrupted', reason: 'protocol' });
  });

  it('preserves binary channel payload and waits for renderer drain before publishing a validated exit', () => {
    const rendered: { channel: number; bytes: number[] }[] = [];
    const complete: (() => void)[] = [];
    const { socket, connection } = fixture({
      write(channel, bytes, done) {
        rendered.push({ channel, bytes: Array.from(bytes) });
        complete.push(done);
      },
    });
    socket.open();
    socket.ready();
    socket.output(new Uint8Array([0, 0xff, 27, 91, 65]), 1);
    socket.message('{"type":"exit","status":7}');
    expect(connection.state().phase).toBe('finishing');
    expect(rendered).toEqual([{ channel: 1, bytes: [0, 255, 27, 91, 65] }]);
    required(complete[0])();
    expect(connection.state()).toEqual({ phase: 'exited', status: 7 });
  });

  it('never invents success from clean or abnormal close without an exit frame', () => {
    for (const code of [1000, 1006]) {
      const { socket, connection } = fixture();
      socket.open();
      socket.ready();
      socket.serverClose(code);
      expect(connection.state()).toEqual({ phase: 'interrupted', reason: 'connection-lost' });
    }
  });

  it('does not end active execution when new-access permission expires and keeps explicit exit authoritative', () => {
    let available = true;
    const { socket, connection } = fixture(undefined, {
      ...access,
      terminalToken() {
        if (!available) {
          throw new Error();
        }
        return proof;
      },
    });
    socket.open();
    socket.ready();
    available = false;
    vi.advanceTimersByTime(60_000);
    expect(connection.state()).toEqual({ phase: 'connected' });
    expect(connection.input(new Uint8Array([65]))).toBe(true);
    socket.message('{"type":"exit","status":0}');
    socket.onerror?.(new Event('error'));
    socket.serverClose(1006);
    expect(connection.state()).toEqual({ phase: 'exited', status: 0 });
  });

  it('requests exec/no-PTY without broadening management or command/window permissions', () => {
    const command = fixture(undefined, access, {
      kind: 'exec',
      command: 'printf hello',
      pty: false,
    });
    command.socket.open();
    command.socket.ready();
    expect(JSON.parse(command.socket.sent[0] as string)).toEqual({
      type: 'open',
      slug: 'Work',
      accessToken: proof,
      task: 'exec',
      command: 'printf hello',
    });
    expect(command.connection.resize(100, 30)).toBe(false);
    expect(() =>
      fixture(undefined, {
        ...access,
        snapshot: () => ({
          ...access.snapshot(),
          environment: 'management',
          terminalAvailable: false,
        }),
      }),
    ).toThrow();
    expect(() => fixture(undefined, access, { command: 'x\0y' })).toThrow();
    expect(() => fixture(undefined, access, { columns: 0 })).toThrow();
  });

  it('fails closed on duplicate/malformed/unexpected states, statuses or output', () => {
    for (const payload of [
      '{"type":"exit","status":0}',
      '{"type":"ready","connectionId":"wrong"}',
      '{"type":"unknown"}',
      '{"type":"error","code":"private diagnostic"}',
      'null',
    ]) {
      const { socket, connection } = fixture();
      socket.open();
      socket.message(payload);
      expect(connection.state().phase).toBe('interrupted');
    }
    for (const payload of [
      '{"type":"exit","status":-1}',
      '{"type":"exit","status":4294967296}',
      '{"type":"exit","status":null}',
      '{"type":"exit","status":0,"extra":true}',
      JSON.stringify({ type: 'ready', connectionId: uuid }),
    ]) {
      const { socket, connection } = fixture();
      socket.open();
      socket.ready();
      socket.message(payload);
      expect(connection.state()).toEqual({ phase: 'interrupted', reason: 'protocol' });
    }
    const early = fixture();
    early.socket.open();
    early.socket.output(new Uint8Array([65]));
    expect(early.connection.state().phase).toBe('interrupted');
    const wrong = fixture();
    wrong.socket.open();
    wrong.socket.ready();
    wrong.socket.output(new Uint8Array([65]), 2);
    expect(wrong.connection.state().phase).toBe('interrupted');
  });

  it('bounds output and closes instead of accumulating behind an unresponsive renderer', () => {
    const blocked = fixture({ write() {} });
    blocked.socket.open();
    blocked.socket.ready();
    for (let index = 0; index < 17; index++) {
      blocked.socket.output(new Uint8Array(16383));
    }
    expect(blocked.connection.state()).toEqual({ phase: 'interrupted', reason: 'output-limit' });
    const slow = fixture({ write() {} });
    slow.socket.open();
    slow.socket.ready();
    slow.socket.output(new Uint8Array([65]));
    vi.advanceTimersByTime(5001);
    expect(slow.connection.state()).toEqual({ phase: 'interrupted', reason: 'output-limit' });
  });

  it('paces copied stdin and preserves queued input before one EOF without replay', () => {
    const { socket, connection } = fixture();
    socket.open();
    socket.ready();
    const bytes = new Uint8Array(16 << 10).fill(65);
    expect(connection.input(bytes)).toBe(true);
    bytes.fill(90);
    expect(connection.eof()).toBe(true);
    expect(connection.eof()).toBe(false);
    expect(connection.input(new Uint8Array([66]))).toBe(false);
    vi.advanceTimersByTime(1000);
    const frames = socket.sent.slice(1);
    expect(
      frames
        .slice(0, 4)
        .every((frame) => frame instanceof Uint8Array && frame.length === 4096 && frame[0] === 65),
    ).toBe(true);
    expect(JSON.parse(frames[4] as string)).toEqual({ type: 'eof' });
    expect(frames).toHaveLength(5);
  });

  it('bounds input/control queues and socket backpressure without dropping data', () => {
    const overflow = fixture();
    overflow.socket.open();
    overflow.socket.ready();
    overflow.connection.input(new Uint8Array((64 << 10) + 1));
    expect(overflow.connection.state()).toEqual({ phase: 'interrupted', reason: 'input-limit' });
    const controls = fixture();
    controls.socket.open();
    controls.socket.ready();
    for (let index = 0; index < 18; index++) {
      controls.connection.signal('INT');
    }
    expect(controls.connection.state()).toEqual({ phase: 'interrupted', reason: 'input-limit' });
    const pressure = fixture();
    pressure.socket.open();
    pressure.socket.ready();
    pressure.socket.bufferedAmount = 40 << 10;
    pressure.connection.input(new Uint8Array([65]));
    vi.advanceTimersByTime(5100);
    expect(pressure.connection.state()).toEqual({ phase: 'interrupted', reason: 'input-limit' });
  });

  it('coalesces unsent resize, sends only supported signals and has owned timeout/disconnect/cleanup', () => {
    const { socket, connection } = fixture();
    socket.open();
    socket.ready();
    socket.bufferedAmount = 40 << 10;
    connection.resize(100, 30);
    connection.resize(120, 35);
    socket.bufferedAmount = 0;
    vi.advanceTimersByTime(100);
    expect(JSON.parse(socket.sent[1] as string)).toEqual({
      type: 'resize',
      columns: 120,
      rows: 35,
    });
    expect(connection.resize(0, 10)).toBe(false);
    connection.disconnect();
    expect(connection.state()).toEqual({ phase: 'disconnected' });
    const count = socket.sent.length;
    vi.advanceTimersByTime(30_000);
    expect(socket.sent).toHaveLength(count);
    const timeout = fixture();
    vi.advanceTimersByTime(20_001);
    expect(timeout.connection.state()).toEqual({ phase: 'interrupted', reason: 'timeout' });
  });

  it('does not publish stale renderer callbacks after disposal', () => {
    let done!: () => void;
    const { socket, connection, states } = fixture({
      write(_channel, _bytes, complete) {
        done = complete;
      },
    });
    socket.open();
    socket.ready();
    socket.output(new Uint8Array([65]));
    connection.dispose();
    const count = states.length;
    done();
    vi.advanceTimersByTime(6000);
    expect(states).toHaveLength(count);
  });
});

describe('per-instance CSP document adapter', () => {
  it('adds a nonce before xterm inserts styles without mutating global DOM factories', () => {
    const nonce = `${'A'.repeat(43)}=`;
    const scoped = noncedDocument(document, nonce);
    expect(scoped instanceof Document).toBe(true);
    expect(scoped.createElement('style').nonce).toBe(nonce);
    expect(document.createElement('style').nonce).toBe('');
    expect(scoped.createElement('div').ownerDocument).toBe(document);
    expect(scoped.body).toBe(document.body);
    expect(() => noncedDocument(document, 'bad')).toThrow();
  });
});
