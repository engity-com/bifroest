import { afterEach, describe, expect, it, vi } from 'vitest';
import { transferMediaType } from '../src/artifacts/protocol';
import { WebAccess } from '../src/remember/client';
import { Http } from '../src/remember/http';
import { required } from './required';

const scope = { origin: 'https://app.example.org:8443', slug: 'Work' };
const request = {
  kind: 'recording',
  auditlog: 'default',
  id: '34e34ab8-7457-4d88-a5e4-c57791775c3a',
} as const;
const permission = {
  scope,
  principal: 'alice',
  expiresAt: '2100-01-01T00:00:00Z',
  environment: 'management' as const,
  terminalAvailable: false,
  accessToken: `bwa1.${'A'.repeat(43)}`,
};

class HeldWorker extends EventTarget {
  static instances: HeldWorker[] = [];
  terminated = false;
  constructor() {
    super();
    HeldWorker.instances.push(this);
    queueMicrotask(() =>
      this.dispatchEvent(new MessageEvent('message', { data: { kind: 'ready' } })),
    );
  }
  postMessage() {}
  terminate() {
    this.terminated = true;
  }
}

afterEach(() => {
  vi.unstubAllGlobals();
  HeldWorker.instances = [];
});

describe('opaque artifact permission ownership', () => {
  it('refuses non-management/expired access without any worker or fetch', async () => {
    vi.stubGlobal('Worker', HeldWorker);
    const transport = vi.fn(async () => new Response());
    for (const response of [
      { ...permission, environment: 'terminal' as const, terminalAvailable: true },
      { ...permission, expiresAt: '2000-01-01T00:00:00Z' },
    ]) {
      await expect(
        new WebAccess(new Http(scope, transport), response, null).downloadArtifact(request),
      ).rejects.toMatchObject({ code: 'denied' });
    }
    expect(transport).not.toHaveBeenCalled();
    expect(HeldWorker.instances).toHaveLength(0);
  });

  it('limits one staged operation, aborts it on logout and joins its fetch cleanup before success', async () => {
    vi.stubGlobal('Worker', HeldWorker);
    let entered: (() => void) | undefined;
    const reading = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let release: (() => void) | undefined;
    const cleaning = new Promise<void>((resolve) => {
      release = resolve;
    });
    let cancellations = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull() {
        entered?.();
      },
      cancel() {
        cancellations++;
        return cleaning;
      },
    });
    const transport = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).endsWith('/logout')) {
        return new Response(null, { status: 204 });
      }
      const response = new Response(stream, {
        status: 200,
        headers: { 'Content-Type': transferMediaType },
      });
      Object.defineProperty(response, 'url', {
        value: `${scope.origin}/_bifroest/api/v1/management/artifacts/recording`,
      });
      return response;
    });
    const access = new WebAccess(new Http(scope, transport), permission, null);
    const operation = access.downloadArtifact(request);
    const rejected = expect(operation).rejects.toMatchObject({ code: 'cancelled' });
    await reading;
    await expect(access.downloadArtifact(request)).rejects.toMatchObject({ code: 'busy' });
    let loggedOut = false;
    const logout = access.logout().finally(() => {
      loggedOut = true;
    });
    await vi.waitFor(() => expect(cancellations).toBe(1));
    expect(loggedOut).toBe(false);
    expect(required(HeldWorker.instances[0]).terminated).toBe(true);
    release?.();
    await rejected;
    await expect(logout).resolves.toEqual({ localState: 'not-owned' });
    expect(stream.locked).toBe(false);
    await expect(access.downloadArtifact(request)).rejects.toMatchObject({ code: 'denied' });
    expect(JSON.stringify(access)).not.toContain('bwa1.');
  });
});
