import { object } from '../remember/http';
import { expectedFiles, transferMetadata } from './metadata';
import type { ArtifactRequest } from './protocol';
import { artifactFields, maximumTransferImageBytes, transferMediaType } from './protocol';

type Runtime = {
  Go: new () => {
    importObject: WebAssembly.Imports;
    run(instance: WebAssembly.Instance): Promise<void>;
    exit: (code: number) => void;
  };
  bifroestTransferReceive: (...args: unknown[]) => unknown;
};
const runtime = globalThis as unknown as Runtime;
const worker = globalThis as unknown as {
  postMessage(value: unknown): void;
  close(): void;
  onmessage: ((event: MessageEvent) => void) | null;
};
let used = false;

function fail(reason: 'unavailable' | 'too-large' = 'unavailable') {
  worker.postMessage({ kind: 'failed', reason });
  worker.close();
}

worker.onmessage = (event) => {
  try {
    if (used) {
      throw new Error();
    }
    used = true;
    const body = object(event.data, ['kind', 'request', 'bytes', 'mediaType', 'status']);
    const request = body.request as ArtifactRequest;
    artifactFields(request);
    if (
      body.kind !== 'receive' ||
      !(body.bytes instanceof ArrayBuffer) ||
      body.bytes.byteLength > maximumTransferImageBytes ||
      body.mediaType !== transferMediaType ||
      body.status !== 200
    ) {
      throw new Error();
    }
    const input = new Uint8Array(body.bytes);
    let result: unknown;
    try {
      result = runtime.bifroestTransferReceive(
        request.kind,
        request.auditlog,
        request.kind === 'recording' ? request.id : '',
        input,
        body.mediaType,
        body.status,
      );
    } finally {
      input.fill(0);
    }
    if (result === null || typeof result !== 'object') {
      throw new Error();
    }
    if ('ok' in result && result.ok === false) {
      if ('code' in result && result.code === 'too-large') {
        fail('too-large');
      } else {
        fail();
      }
      return;
    }
    const decoded = object(result, ['ok', 'metadata', 'files']);
    if (
      decoded.ok !== true ||
      typeof decoded.metadata !== 'string' ||
      !Array.isArray(decoded.files)
    ) {
      throw new Error();
    }
    const metadata = transferMetadata(request, JSON.parse(decoded.metadata));
    const entries = expectedFiles(metadata);
    if (entries.length !== decoded.files.length) {
      throw new Error();
    }
    const files = decoded.files.map((value, index) => {
      const file = object(value, ['name', 'data']);
      const entry = entries[index];
      if (
        entry === undefined ||
        file.name !== entry.name ||
        !(file.data instanceof Uint8Array) ||
        !(file.data.buffer instanceof ArrayBuffer) ||
        file.data.byteOffset !== 0 ||
        file.data.byteLength !== file.data.buffer.byteLength ||
        file.data.byteLength !== entry.size
      ) {
        throw new Error();
      }
      return {
        name: entry.name,
        data: new Blob([file.data.buffer], { type: 'application/octet-stream' }),
      };
    });
    worker.postMessage({ kind: 'received', metadata, files });
    worker.close();
  } catch {
    fail();
  }
};

async function boot() {
  await import(/* @vite-ignore */ new URL('go-wasm-exec.js', location.href).href);
  const url = new URL('browser-transfer.wasm', location.href);
  const response = await fetch(url, {
    credentials: 'omit',
    mode: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    signal: AbortSignal.timeout(20_000),
  });
  if (
    response.status !== 200 ||
    response.redirected ||
    response.url !== url.href ||
    response.headers.get('Content-Type') !== 'application/wasm' ||
    response.headers.has('Content-Encoding') ||
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
      size += part.value.byteLength;
      if (size > 8 << 20) {
        throw new Error();
      }
      chunks.push(part.value);
    }
  } finally {
    try {
      await reader.cancel();
    } finally {
      reader.releaseLock();
    }
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const go = new runtime.Go();
  go.exit = () => fail();
  const instantiated = await WebAssembly.instantiate(bytes, go.importObject);
  void go.run(instantiated.instance).catch(() => fail());
}

void boot().catch(() => fail());
