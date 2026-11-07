import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { BrowserBinding, BrowserClient } from '../src/remember';
import { WebAccess } from '../src/remember/client';
import { Http } from '../src/remember/http';
import type { Socket } from '../src/terminal/socket';
import { TerminalConnection } from '../src/terminal/socket';
import { useAccessStatus } from '../src/ui/use-access-status';

const scope = { origin: 'https://app.example.org', slug: 'Manage' };
const start = Date.parse('2026-11-03T12:00:00Z');
const cleanups: (() => void)[] = [];

beforeEach(() => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  vi.useFakeTimers({
    toFake: ['Date', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'],
  });
  vi.setSystemTime(start);
});
afterEach(async () => {
  await act(async () => {
    for (const cleanup of cleanups.splice(0).reverse()) {
      cleanup();
    }
  });
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function permission(terminal = false) {
  const transport = vi.fn(async () => new Response(null, { status: 503 }));
  const access = new WebAccess(
    new Http(scope, transport),
    {
      scope,
      principal: 'manager',
      accessToken: `bwa1.${'A'.repeat(43)}`,
      expiresAt: new Date(start + 600_000).toISOString(),
      environment: terminal ? 'terminal' : 'management',
      terminalAvailable: terminal,
    },
    null,
  );
  return { access, transport };
}

function Probe({ access }: { access: WebAccess }) {
  return createElement('output', null, useAccessStatus(access));
}

async function observe(access: WebAccess) {
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  cleanups.push(() => {
    root.unmount();
    container.remove();
  });
  await act(async () => root.render(createElement(Probe, { access })));
  return container;
}

describe('local web-grant lifetime observation', () => {
  it('checks the exact deadline without a UI or any network request', async () => {
    const { access, transport } = permission();
    expect(access.status()).toBe('active');
    vi.advanceTimersByTime(599_999);
    expect(access.status()).toBe('active');
    vi.advanceTimersByTime(1);
    expect(access.status()).toBe('expired');
    await expect(access.managementVersion()).rejects.toMatchObject({ code: 'denied' });
    expect(transport).not.toHaveBeenCalled();
    expect(JSON.stringify(access)).not.toContain('bwa1.');
  });

  it('does not adopt a later server session validUntil as the web-grant deadline', async () => {
    const { access, transport } = permission();
    const id = '70d5159d-a0e4-46ca-b011-c4f831f4ade0';
    const validUntil = new Date(start + 1_800_000).toISOString();
    transport.mockImplementation(
      async () =>
        new Response(
          JSON.stringify({
            version: 1,
            operation: 'sessions.show',
            session: {
              id,
              flow: 'worker',
              state: 'authorized',
              user: 'requested',
              remote: '',
              createdAt: new Date(start).toISOString(),
              owner: null,
              validUntil,
            },
          }),
          { headers: { 'Content-Type': 'application/json' } },
        ),
    );
    expect((await access.managementSession('worker', id)).validUntil).toBe(validUntil);
    vi.advanceTimersByTime(600_000);
    expect(access.status()).toBe('expired');
    expect(Date.now()).toBeLessThan(Date.parse(validUntil));
    await expect(access.managementSession('worker', id)).rejects.toMatchObject({ code: 'denied' });
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('updates at the exact web deadline without network, saved reads, resume or token exposure', async () => {
    const saved = vi.spyOn(BrowserBinding, 'load');
    const resume = vi.spyOn(BrowserClient.prototype, 'resume');
    const fetch = vi.spyOn(globalThis, 'fetch');
    const { access, transport } = permission();
    const container = await observe(access);
    expect(container.textContent).toBe('active');
    await act(async () => vi.advanceTimersByTime(599_999));
    expect(container.textContent).toBe('active');
    await act(async () => vi.advanceTimersByTime(1));
    expect(container.textContent).toBe('expired');
    expect(access.status()).toBe('expired');
    await expect(access.managementVersion()).rejects.toMatchObject({ code: 'denied' });
    expect(transport).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
    expect(saved).not.toHaveBeenCalled();
    expect(resume).not.toHaveBeenCalled();
    expect(JSON.stringify(access)).not.toContain('bwa1.');
  });

  it.each(['focus', 'visibilitychange'])('rechecks a suspended deadline on %s', async (event) => {
    const { access, transport } = permission();
    const container = await observe(access);
    vi.setSystemTime(start + 600_001); // No timer callback: model a suspended background tab.
    await act(async () => {
      (event === 'focus' ? window : document).dispatchEvent(new Event(event));
    });
    expect(container.textContent).toBe('expired');
    expect(transport).not.toHaveBeenCalled();
  });

  it('publishes local closure immediately even when server logout fails', async () => {
    const { access, transport } = permission();
    const container = await observe(access);
    await act(async () => {
      const logout = access.logout();
      expect(access.status()).toBe('closed');
      await expect(logout).rejects.toMatchObject({ code: 'unavailable' });
    });
    expect(container.textContent).toBe('closed');
    expect(transport).toHaveBeenCalledTimes(1);
    await act(async () => vi.advanceTimersByTime(600_001));
    expect(container.textContent).toBe('closed');
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('does not interpret an operation policy denial as grant expiry or closure', async () => {
    const { access, transport } = permission();
    transport.mockImplementation(async () => new Response(null, { status: 403 }));
    await expect(access.managementVersion()).rejects.toMatchObject({ code: 'denied' });
    expect(access.status()).toBe('active');
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('leaves an already running terminal socket and its input/output alive after web expiry', async () => {
    const { access, transport } = permission(true);
    const sent: (string | Uint8Array)[] = [];
    const close = vi.fn();
    const socket: Socket = {
      binaryType: 'arraybuffer',
      protocol: 'bifroest-terminal.v1',
      readyState: 1,
      bufferedAmount: 0,
      onopen: null,
      onmessage: null,
      onerror: null,
      onclose: null,
      send: (data) => sent.push(data),
      close,
    };
    const output: number[][] = [];
    const connection = new TerminalConnection(
      access,
      { kind: 'shell', command: '', pty: true, columns: 80, rows: 24 },
      {
        write(_channel, bytes, done) {
          output.push([...bytes]);
          done();
        },
      },
      () => {},
      () => socket,
    );
    cleanups.push(() => connection.dispose());
    socket.onopen?.(new Event('open'));
    socket.onmessage?.(
      new MessageEvent('message', {
        data: JSON.stringify({
          type: 'ready',
          connectionId: '70d5159d-a0e4-46ca-b011-c4f831f4ade0',
        }),
      }),
    );
    await act(async () => vi.advanceTimersByTime(600_001));
    expect(access.status()).toBe('expired');
    expect(connection.state()).toEqual({ phase: 'connected' });
    expect(close).not.toHaveBeenCalled();
    expect(connection.input(new Uint8Array([65]))).toBe(true);
    vi.advanceTimersByTime(120);
    socket.onmessage?.(new MessageEvent('message', { data: new Uint8Array([0, 66]).buffer }));
    expect(output).toEqual([[66]]);
    expect(sent.some((data) => data instanceof Uint8Array)).toBe(true);
    expect(transport).not.toHaveBeenCalled();
  });
});
