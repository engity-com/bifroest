import { object } from '../remember/http';

type Bridge = {
  Go: new () => {
    importObject: WebAssembly.Imports;
    run(instance: WebAssembly.Instance): Promise<void>;
    exit: (code: number) => void;
  };
  bifroestKeyImport: (...args: unknown[]) => unknown;
  bifroestKeySign: (...args: unknown[]) => unknown;
};
const runtime = globalThis as unknown as Bridge;
const worker = globalThis as unknown as {
  postMessage(value: unknown): void;
  close(): void;
  onmessage: ((event: MessageEvent) => void) | null;
};
let imported = false;
const fail = () => {
  worker.postMessage({ kind: 'failed' });
  worker.close();
};

// Never forward Go/parser exceptions, buffers or provider-controlled messages.
worker.onmessage = (event) => {
  try {
    const message = event.data as Record<string, unknown>;
    if (!imported) {
      const body = object(message, [
        'kind',
        'privateKey',
        'passphrase',
        'certificate',
        'origin',
        'slug',
        'user',
      ]);
      if (
        body.kind !== 'import' ||
        body.origin !== location.origin ||
        typeof body.slug !== 'string' ||
        typeof body.user !== 'string'
      ) {
        throw new Error();
      }
      imported = true;
      const buffers = [body.privateKey, body.passphrase, body.certificate];
      if (buffers.some((value) => !(value instanceof ArrayBuffer))) {
        throw new Error();
      }
      const bytes = buffers.map((buffer) => new Uint8Array(buffer as ArrayBuffer));
      let result: Record<string, unknown>;
      try {
        result = object(runtime.bifroestKeyImport(...bytes, body.origin, body.slug, body.user), [
          'ok',
          'publicKey',
          'fingerprint',
        ]);
      } finally {
        for (const value of bytes) {
          value.fill(0);
        }
      }
      if (
        result.ok !== true ||
        typeof result.publicKey !== 'string' ||
        typeof result.fingerprint !== 'string'
      ) {
        throw new Error();
      }
      worker.postMessage({
        kind: 'imported',
        publicKey: result.publicKey,
        fingerprint: result.fingerprint,
      });
    } else {
      const body = object(message, ['kind', 'challenge', 'expiresAt']);
      if (
        body.kind !== 'sign' ||
        typeof body.challenge !== 'string' ||
        typeof body.expiresAt !== 'string'
      ) {
        throw new Error();
      }
      const result = object(runtime.bifroestKeySign(body.challenge, body.expiresAt), [
        'ok',
        'signature',
      ]);
      if (result.ok !== true || typeof result.signature !== 'string') {
        throw new Error();
      }
      worker.postMessage({ kind: 'signed', signature: result.signature });
      worker.close();
    }
  } catch {
    fail();
  }
};

async function boot() {
  await import(/* @vite-ignore */ new URL('go-wasm-exec.js', location.href).href);
  const response = await fetch(new URL('browser-key.wasm', location.href), {
    credentials: 'omit',
    mode: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    signal: AbortSignal.timeout(20_000),
  });
  if (
    response.status !== 200 ||
    response.redirected ||
    !/^application\/wasm(?:;|$)/iu.test(response.headers.get('Content-Type') ?? '') ||
    response.body === null
  ) {
    throw new Error();
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) {
        break;
      }
      size += part.value.length;
      if (size > 8 << 20) {
        throw new Error();
      }
      chunks.push(part.value);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  const go = new runtime.Go();
  go.exit = fail;
  const result = await WebAssembly.instantiate(bytes, go.importObject);
  void go.run(result.instance).catch(fail);
}
void boot().catch(fail);
