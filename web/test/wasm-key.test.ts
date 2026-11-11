import { afterEach, describe, expect, it, vi } from 'vitest';
import { WasmLoginKey } from '../src/login/wasm-key';
import { required } from './required';

const scope = { origin: location.origin.replace('http:', 'https:'), slug: 'Work' };
const publicKey = btoa('public-wire-fixture');
const fingerprint = `SHA256:${'A'.repeat(43)}`;
class LocalWorker extends EventTarget {
  static instances: LocalWorker[] = [];
  static rejectImport = false;
  static hold = false;
  terminated = false;
  requests: Record<string, unknown>[] = [];
  constructor(_url: string, options: WorkerOptions) {
    super();
    LocalWorker.instances.push(this);
    expect(options).toMatchObject({ type: 'module', credentials: 'omit' });
  }
  send(value: unknown) {
    if (!this.terminated) {
      this.dispatchEvent(new MessageEvent('message', { data: value }));
    }
  }
  postMessage(value: Record<string, unknown>) {
    this.requests.push(value);
    if (value.kind === 'boot') {
      expect(value.wasm).toBeInstanceOf(ArrayBuffer);
      queueMicrotask(() => this.send({ kind: 'ready' }));
    } else if (value.kind === 'import') {
      queueMicrotask(() => {
        if (!LocalWorker.hold) {
          this.send(
            LocalWorker.rejectImport
              ? { kind: 'failed' }
              : { kind: 'imported', publicKey, fingerprint },
          );
        }
      });
    } else {
      queueMicrotask(() => this.send({ kind: 'signed', signature: 'wire-proof-fixture' }));
    }
  }
  terminate() {
    this.terminated = true;
  }
}
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
  LocalWorker.instances = [];
  LocalWorker.rejectImport = false;
  LocalWorker.hold = false;
});

function install() {
  vi.stubGlobal('Worker', LocalWorker);
  vi.stubGlobal(
    'fetch',
    vi.fn(
      async () =>
        new Response(new Uint8Array([0, 97, 115, 109]), {
          headers: { 'Content-Type': 'application/wasm' },
        }),
    ),
  );
}
function file(size = 20) {
  return new File([new Uint8Array(size)], 'private-file');
}

describe('owned WASM key worker lifecycle (RPC fixtures, not cryptographic tests)', () => {
  it('keeps private RPC fields out of serialization, signs once and terminates after use', async () => {
    install();
    const controller = new AbortController();
    const key = await WasmLoginKey.import(file(), 'tab secret', null, scope, '', controller.signal);
    expect(LocalWorker.instances[0]?.requests.map((request) => request.kind)).toEqual([
      'boot',
      'import',
    ]);
    expect(Object.keys(required(LocalWorker.instances[0]?.requests[0])).sort()).toEqual([
      'kind',
      'wasm',
    ]);
    expect(JSON.stringify(key)).toBe(JSON.stringify({ publicKey, fingerprint }));
    expect(JSON.stringify(key)).not.toContain('tab secret');
    expect(await key.sign('server-challenge', 'expiry', controller.signal)).toBe(
      'wire-proof-fixture',
    );
    expect(required(LocalWorker.instances[0]).terminated).toBe(true);
    await expect(key.sign('server-challenge', 'expiry', controller.signal)).rejects.toMatchObject({
      code: 'invalid-proof',
    });
  });

  it('rejects oversized keys/passphrases and a selected empty/oversized certificate before creating a worker', async () => {
    install();
    const signal = new AbortController().signal;
    for (const args of [
      [file(65537), '', null],
      [file(), '€'.repeat(1400), null],
      [file(), '', file(0)],
      [file(), '', file(12289)],
    ] as const) {
      await expect(
        WasmLoginKey.import(args[0], args[1], args[2], scope, '', signal),
      ).rejects.toMatchObject({ code: 'key-import' });
    }
    expect(LocalWorker.instances).toHaveLength(0);
  });

  it('terminates on a failed local import and never exposes parser diagnostics', async () => {
    install();
    LocalWorker.rejectImport = true;
    await expect(
      WasmLoginKey.import(file(), 'wrong secret', null, scope, '', new AbortController().signal),
    ).rejects.toMatchObject({ code: 'key-import', phase: 'key-import' });
    expect(required(LocalWorker.instances[0]).terminated).toBe(true);
  });

  it('classifies a failed public download without turning its own cleanup into caller cancellation', async () => {
    install();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('PRIVATE-TRANSPORT-SENTINEL');
      }),
    );
    await expect(
      WasmLoginKey.import(file(), 'secret', null, scope, '', new AbortController().signal),
    ).rejects.toMatchObject({ code: 'key-import', phase: 'wasm-download' });
    expect(LocalWorker.instances).toHaveLength(0);
  });

  it('distinguishes local file read and worker construction failures without forwarding their text', async () => {
    install();
    const read = vi.spyOn(FileReader.prototype, 'readAsArrayBuffer').mockImplementation(() => {
      throw new Error('PRIVATE-FILE-SENTINEL');
    });
    await expect(
      WasmLoginKey.import(file(), 'secret', null, scope, '', new AbortController().signal),
    ).rejects.toMatchObject({ code: 'key-import', phase: 'file-read' });
    read.mockRestore();
    class RejectedWorker {
      constructor() {
        throw new Error('PRIVATE-WORKER-SENTINEL');
      }
    }
    vi.stubGlobal('Worker', RejectedWorker);
    await expect(
      WasmLoginKey.import(file(), 'secret', null, scope, '', new AbortController().signal),
    ).rejects.toMatchObject({ code: 'key-import', phase: 'worker-start' });
  });

  it('retires an outstanding import immediately on caller abort', async () => {
    install();
    LocalWorker.hold = true;
    const controller = new AbortController();
    const operation = WasmLoginKey.import(file(), 'secret', null, scope, '', controller.signal);
    await vi.waitFor(() =>
      expect(LocalWorker.instances[0]?.requests.some((request) => request.kind === 'import')).toBe(
        true,
      ),
    );
    controller.abort();
    await expect(operation).rejects.toMatchObject({ code: 'cancelled' });
    expect(required(LocalWorker.instances[0]).terminated).toBe(true);
  });

  it('cancels a pending file read before any worker or private transfer exists', async () => {
    install();
    let entered!: () => void;
    const reading = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let reader!: BlockingReader;
    class BlockingReader {
      onload = null;
      onerror = null;
      onabort = null;
      result = null;
      aborted = false;
      constructor() {
        reader = this;
      }
      readAsArrayBuffer() {
        entered();
      }
      abort() {
        this.aborted = true;
      }
    }
    vi.stubGlobal('FileReader', BlockingReader);
    const controller = new AbortController();
    const operation = WasmLoginKey.import(file(), 'secret', null, scope, '', controller.signal);
    await reading;
    controller.abort();
    await expect(operation).rejects.toMatchObject({ code: 'cancelled' });
    expect(reader.aborted).toBe(true);
    expect(LocalWorker.instances).toHaveLength(0);
  });

  it('cancels a pending public download before reading keys or creating a secret worker', async () => {
    install();
    const read = vi.fn();
    class UnexpectedReader {
      readAsArrayBuffer = read;
    }
    vi.stubGlobal('FileReader', UnexpectedReader);
    const fetch = vi.fn(
      (_url, options) =>
        new Promise<Response>((_resolve, reject) => {
          options.signal.addEventListener('abort', () => reject(new Error('provider detail')), {
            once: true,
          });
        }),
    );
    vi.stubGlobal('fetch', fetch);
    const controller = new AbortController();
    const operation = WasmLoginKey.import(file(), 'secret', null, scope, '', controller.signal);
    const observed = expect(operation).rejects.toMatchObject({ code: 'cancelled' });
    controller.abort();
    await observed;
    expect(read).not.toHaveBeenCalled();
    expect(LocalWorker.instances).toHaveLength(0);
    expect(fetch).toHaveBeenCalledOnce();
  });

  it('enforces the bounded RPC deadline even if the worker does not answer', async () => {
    install();
    LocalWorker.hold = true;
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    vi.spyOn(AbortSignal, 'timeout').mockImplementation((milliseconds) => {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), milliseconds);
      return controller.signal;
    });
    const operation = WasmLoginKey.import(
      file(),
      'secret',
      null,
      scope,
      '',
      new AbortController().signal,
    );
    const observed = expect(operation).rejects.toMatchObject({ code: 'key-import' });
    await vi.waitFor(() =>
      expect(LocalWorker.instances[0]?.requests.some((request) => request.kind === 'import')).toBe(
        true,
      ),
    );
    await vi.advanceTimersByTimeAsync(20_001);
    await observed;
    expect(required(LocalWorker.instances[0]).terminated).toBe(true);
  });
});
