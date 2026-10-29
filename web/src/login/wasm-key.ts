import { object } from '../remember/http';
import type { Scope } from '../remember/protocol';
import { decode64, RememberMeError } from '../remember/protocol';
import { readLocalBytes } from '../wasm/local-file';
import type { LoginKey } from './key';
import { loadLoginWasm } from './wasm-image';

export class WasmLoginKey implements LoginKey {
  readonly publicKey: string;
  readonly fingerprint: string;
  readonly #worker: Worker;
  readonly #lifetime: AbortController;
  readonly #signal: AbortSignal;
  #used = false;

  private constructor(
    worker: Worker,
    lifetime: AbortController,
    signal: AbortSignal,
    publicKey: string,
    fingerprint: string,
  ) {
    this.#worker = worker;
    this.#lifetime = lifetime;
    this.#signal = signal;
    this.publicKey = publicKey;
    this.fingerprint = fingerprint;
  }

  static async import(
    privateFile: File,
    passphrase: string,
    certificateFile: File | null,
    scope: Scope,
    user: string,
    signal: AbortSignal,
  ): Promise<WasmLoginKey> {
    if (
      privateFile.size < 1 ||
      privateFile.size > 64 << 10 ||
      (certificateFile !== null && (certificateFile.size < 1 || certificateFile.size > 12 << 10)) ||
      passphrase.length > 4096 ||
      !passphrase.isWellFormed() ||
      user.length > 256
    ) {
      throw new RememberMeError('key-import');
    }
    const password = new TextEncoder().encode(passphrase);
    if (password.length > 4096) {
      password.fill(0);
      throw new RememberMeError('key-import');
    }
    let worker: Worker | undefined;
    const lifetime = new AbortController();
    const stopped = AbortSignal.any([signal, lifetime.signal, AbortSignal.timeout(120_000)]);
    let privateBytes: ArrayBuffer | undefined;
    let certificate: ArrayBuffer | undefined;
    try {
      if (stopped.aborted) {
        throw new RememberMeError('cancelled');
      }
      const wasm = await loadLoginWasm(stopped);
      privateBytes = await readLocalBytes(privateFile, stopped);
      certificate =
        certificateFile === null
          ? new ArrayBuffer(0)
          : await readLocalBytes(certificateFile, stopped);
      if (privateBytes.byteLength > 64 << 10 || certificate.byteLength > 12 << 10) {
        throw new RememberMeError('key-import');
      }
      if (stopped.aborted) {
        throw new RememberMeError('cancelled');
      }
      worker = new Worker('/_bifroest/files/browser-key-worker.js', {
        type: 'module',
        credentials: 'omit',
        name: 'bifroest-key',
      });
      const selected = worker;
      stopped.addEventListener('abort', () => selected.terminate(), { once: true });
      await exchange(worker, 'ready', { kind: 'boot', wasm }, stopped, [wasm]);
      const result = await exchange(
        worker,
        'imported',
        {
          kind: 'import',
          privateKey: privateBytes,
          passphrase: password.buffer,
          certificate,
          origin: scope.origin,
          slug: scope.slug,
          user,
        },
        stopped,
        [privateBytes, password.buffer, certificate],
      );
      if (
        typeof result.publicKey !== 'string' ||
        typeof result.fingerprint !== 'string' ||
        decode64(result.publicKey, 8192).length === 0 ||
        !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(result.fingerprint)
      ) {
        throw new RememberMeError('key-import');
      }
      return new WasmLoginKey(worker, lifetime, stopped, result.publicKey, result.fingerprint);
    } catch (error) {
      lifetime.abort();
      worker?.terminate();
      throw error instanceof RememberMeError
        ? error
        : new RememberMeError(stopped.aborted ? 'cancelled' : 'key-import');
    } finally {
      if (password.byteLength) {
        password.fill(0);
      }
      if (privateBytes?.byteLength) {
        new Uint8Array(privateBytes).fill(0);
      }
      if (certificate?.byteLength) {
        new Uint8Array(certificate).fill(0);
      }
    }
  }

  async sign(challenge: string, expiresAt: string, signal: AbortSignal): Promise<string> {
    if (this.#used) {
      throw new RememberMeError('invalid-proof');
    }
    this.#used = true;
    try {
      const result = await exchange(
        this.#worker,
        'signed',
        { kind: 'sign', challenge, expiresAt },
        AbortSignal.any([signal, this.#signal]),
      );
      if (typeof result.signature !== 'string') {
        throw new RememberMeError('invalid-proof');
      }
      return result.signature;
    } finally {
      this.close();
    }
  }
  close() {
    this.#lifetime.abort();
    this.#worker.terminate();
  }
  toJSON() {
    return { publicKey: this.publicKey, fingerprint: this.fingerprint };
  }
}

function exchange(
  worker: Worker,
  kind: string,
  request: unknown,
  signal: AbortSignal,
  transfer: Transferable[] = [],
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const stopped = AbortSignal.any([signal, AbortSignal.timeout(20_000)]);
    const cleanup = () => {
      worker.removeEventListener('message', received);
      worker.removeEventListener('error', failed);
      worker.removeEventListener('messageerror', failed);
      stopped.removeEventListener('abort', aborted);
    };
    const failed = (event?: Event) => {
      event?.preventDefault();
      cleanup();
      worker.terminate();
      reject(new RememberMeError('key-import'));
    };
    const aborted = () => {
      cleanup();
      worker.terminate();
      reject(new RememberMeError(signal.aborted ? 'cancelled' : 'key-import'));
    };
    const received = (event: MessageEvent) => {
      try {
        const expected =
          kind === 'ready'
            ? ['kind']
            : kind === 'imported'
              ? ['kind', 'publicKey', 'fingerprint']
              : ['kind', 'signature'];
        const result = object(event.data, expected);
        if (result.kind !== kind || stopped.aborted) {
          throw new Error();
        }
        cleanup();
        resolve(result);
      } catch {
        failed();
      }
    };
    worker.addEventListener('message', received);
    worker.addEventListener('error', failed);
    worker.addEventListener('messageerror', failed);
    stopped.addEventListener('abort', aborted, { once: true });
    if (stopped.aborted) {
      aborted();
      return;
    }
    try {
      if (request !== undefined) {
        worker.postMessage(request, transfer);
      }
    } catch {
      failed();
    }
  });
}
