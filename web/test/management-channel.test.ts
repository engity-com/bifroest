import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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
    this.json({ type: 'ready', connectionId: id, keepAlive: { interval: '15s', locked: false } });
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
      'wss://app.example.org:8443/_bifroest/api/v1/management/channel',
      'bifroest-management.v1',
    );
    expect(socket.sent[0]).toEqual({ type: 'open', slug: 'Work', accessToken: token });
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
