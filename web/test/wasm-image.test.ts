import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadLoginWasm } from '../src/login/wasm-image';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

const image = () =>
  new Response(new Uint8Array([0, 97, 115, 109]), {
    headers: { 'Content-Type': 'application/wasm' },
  });

describe('tab-owned public WASM transport, not a cryptographic verifier', () => {
  function deadlineTimers() {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    vi.spyOn(AbortSignal, 'timeout').mockImplementation((milliseconds) => {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), milliseconds);
      return controller.signal;
    });
  }

  it('fetches once from the fixed same-origin asset without credentials, redirects or cache', async () => {
    const fetch = vi.fn(async () => image());
    vi.stubGlobal('fetch', fetch);
    const bytes = await loadLoginWasm(new AbortController().signal);
    expect(new Uint8Array(bytes)).toEqual(new Uint8Array([0, 97, 115, 109]));
    expect(fetch).toHaveBeenCalledExactlyOnceWith(
      '/_bifroest/files/browser-key.wasm',
      expect.objectContaining({
        credentials: 'omit',
        mode: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it('does not abort a completed request when the key lifetime ends', async () => {
    let transport!: AbortSignal;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url, options) => {
        transport = options.signal;
        return image();
      }),
    );
    const lifetime = new AbortController();
    await loadLoginWasm(lifetime.signal);
    lifetime.abort();
    expect(transport.aborted).toBe(false);
  });

  it('propagates caller cancellation while a public request is incomplete, without retry', async () => {
    let transport!: AbortSignal;
    const fetch = vi.fn(
      (_url, options) =>
        new Promise<Response>((_resolve, reject) => {
          transport = options.signal;
          transport.addEventListener('abort', () => reject(new Error('cancelled')), { once: true });
        }),
    );
    vi.stubGlobal('fetch', fetch);
    const lifetime = new AbortController();
    const operation = loadLoginWasm(lifetime.signal);
    const observed = expect(operation).rejects.toThrow('cancelled');
    lifetime.abort();
    await observed;
    expect(transport.aborted).toBe(true);
    expect(fetch).toHaveBeenCalledOnce();
  });

  it('keeps the twenty-second loading deadline and detaches it after completion', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    vi.spyOn(AbortSignal, 'timeout').mockImplementation((milliseconds) => {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), milliseconds);
      return controller.signal;
    });
    let completed!: AbortSignal;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url, options) => {
        completed = options.signal;
        return image();
      }),
    );
    await loadLoginWasm(new AbortController().signal);
    await vi.advanceTimersByTimeAsync(20_001);
    expect(completed.aborted).toBe(false);
    let pending!: AbortSignal;
    const fetch = vi.fn(
      (_url, options) =>
        new Promise<Response>((_resolve, reject) => {
          pending = options.signal;
          pending.addEventListener('abort', () => reject(new Error('deadline')), { once: true });
        }),
    );
    vi.stubGlobal('fetch', fetch);
    const observed = expect(loadLoginWasm(new AbortController().signal)).rejects.toThrow(
      'deadline',
    );
    await vi.advanceTimersByTimeAsync(20_001);
    await observed;
    expect(pending.aborted).toBe(true);
    expect(fetch).toHaveBeenCalledOnce();
  });

  it('rejects invalid status, content type, redirected or absent bodies without retry', async () => {
    const redirected = image();
    Object.defineProperty(redirected, 'redirected', { value: true });
    for (const response of [
      new Response('failure', { status: 500 }),
      new Response('not wasm'),
      new Response(null, { headers: { 'Content-Type': 'application/wasm' } }),
      redirected,
    ]) {
      let transport!: AbortSignal;
      const fetch = vi.fn(async (_url, options) => {
        transport = options.signal;
        return response;
      });
      vi.stubGlobal('fetch', fetch);
      await expect(loadLoginWasm(new AbortController().signal)).rejects.toThrow('Invalid WASM');
      expect(transport.aborted).toBe(true);
      expect(fetch).toHaveBeenCalledOnce();
    }
  });

  it('cancels an oversized body and does not raise the existing eight-MiB ceiling', async () => {
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array((8 << 20) + 1));
      },
      cancel,
    });
    const response = new Response(body, { headers: { 'Content-Type': 'application/wasm' } });
    const nativeConsumer = vi.spyOn(response, 'arrayBuffer');
    const fetch = vi.fn(async () => response);
    vi.stubGlobal('fetch', fetch);
    await expect(loadLoginWasm(new AbortController().signal)).rejects.toThrow('byte limit');
    expect(cancel).toHaveBeenCalledOnce();
    // The tee owns the source lock; assert real source cancellation and that
    // an oversized image never reaches the native allocation/consumer path.
    expect(nativeConsumer).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledOnce();
  });

  it('does not start any request for an already cancelled operation', async () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    await expect(loadLoginWasm(AbortSignal.abort())).rejects.toThrow('cancelled');
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each(['caller', 'deadline'])(
    'propagates %s abort while a real cloned body is still being read',
    async (stop) => {
      if (stop === 'deadline') {
        deadlineTimers();
      }
      const entered = Promise.withResolvers<void>();
      let source!: ReadableStreamDefaultController<Uint8Array>;
      const body = new ReadableStream<Uint8Array>(
        {
          start(controller) {
            source = controller;
            controller.enqueue(new Uint8Array([0, 97, 115, 109]));
          },
          pull() {
            entered.resolve();
          },
        },
        { highWaterMark: 0 },
      );
      const response = new Response(body, { headers: { 'Content-Type': 'application/wasm' } });
      const nativeConsumer = vi.spyOn(response, 'arrayBuffer');
      let transportSignal!: AbortSignal;
      const fetch = vi.fn(async (_url, options) => {
        transportSignal = options.signal;
        transportSignal.addEventListener(
          'abort',
          () => source.error(new Error('body read aborted')),
          { once: true },
        );
        return response;
      });
      vi.stubGlobal('fetch', fetch);
      const caller = new AbortController();
      const operation = loadLoginWasm(caller.signal);
      const observed = expect(operation).rejects.toThrow('body read aborted');
      await entered.promise;
      if (stop === 'caller') {
        caller.abort();
      } else {
        await vi.advanceTimersByTimeAsync(20_001);
      }
      await observed;
      expect(transportSignal.aborted).toBe(true);
      expect(nativeConsumer).not.toHaveBeenCalled();
      expect(fetch).toHaveBeenCalledOnce();
    },
  );

  it.each(['caller', 'deadline'])(
    'propagates %s abort after clone EOF while native consumption is pending',
    async (stop) => {
      if (stop === 'deadline') {
        deadlineTimers();
      }
      const response = image();
      const entered = Promise.withResolvers<void>();
      let transportSignal!: AbortSignal;
      const nativeConsumer = vi.spyOn(response, 'arrayBuffer').mockImplementation(
        () =>
          new Promise<ArrayBuffer>((_resolve, reject) => {
            entered.resolve();
            transportSignal.addEventListener(
              'abort',
              () => reject(new Error('native consumption aborted')),
              { once: true },
            );
          }),
      );
      const fetch = vi.fn(async (_url, options) => {
        transportSignal = options.signal;
        return response;
      });
      vi.stubGlobal('fetch', fetch);
      const caller = new AbortController();
      const operation = loadLoginWasm(caller.signal);
      const observed = expect(operation).rejects.toThrow('native consumption aborted');
      await entered.promise;
      if (stop === 'caller') {
        caller.abort();
      } else {
        await vi.advanceTimersByTimeAsync(20_001);
      }
      await observed;
      expect(transportSignal.aborted).toBe(true);
      expect(nativeConsumer).toHaveBeenCalledOnce();
      expect(fetch).toHaveBeenCalledOnce();
    },
  );
});
