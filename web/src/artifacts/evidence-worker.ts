import { object } from '../remember/http';
import { EvidenceError, evidenceMetadata, evidenceOptions } from './evidence-protocol';
import { playbackMetadata, playbackOptions } from './playback-protocol';
import type { ArtifactRequest } from './protocol';
import { artifactFields, maximumBufferedArtifactBytes } from './protocol';

type Runtime = {
  Go: new () => {
    importObject: WebAssembly.Imports;
    run(instance: WebAssembly.Instance): Promise<void>;
    exit: (code: number) => void;
  };
  bifroestEvidenceVerify: (...args: unknown[]) => unknown;
  bifroestEvidencePlayback: (...args: unknown[]) => unknown;
};
const runtime = globalThis as unknown as Runtime;
const worker = globalThis as unknown as {
  postMessage(value: unknown, transfer?: Transferable[]): void;
  close(): void;
  onmessage: ((event: MessageEvent) => void) | null;
};
let used = false;

function failed(code: EvidenceError['code'] = 'verification') {
  worker.postMessage({ kind: 'failed', code });
  worker.close();
}

worker.onmessage = (event) => {
  void process(event).catch(() => failed());
};

async function process(event: MessageEvent) {
  const buffers: Uint8Array<ArrayBuffer>[] = [];
  try {
    if (used) {
      throw new Error();
    }
    used = true;
    if (event.data?.kind === 'playback') {
      const body = object(event.data, ['kind', 'options', 'data']);
      const options = playbackOptions(body.options);
      if (
        !(body.data instanceof Blob) ||
        body.data.size < 1 ||
        body.data.size > maximumBufferedArtifactBytes
      ) {
        throw new EvidenceError('limit');
      }
      const data = new Uint8Array(await body.data.arrayBuffer());
      buffers.push(data);
      const raw = runtime.bifroestEvidencePlayback(
        options.id,
        options.producer,
        options.allowUntrusted,
        data,
      );
      if (raw === null || typeof raw !== 'object') {
        throw new Error();
      }
      if ('ok' in raw && raw.ok === false) {
        const failure = object(raw, ['ok', 'code']);
        failed(
          ['input', 'limit', 'verification'].includes(String(failure.code))
            ? (failure.code as EvidenceError['code'])
            : 'verification',
        );
        return;
      }
      const result = object(raw, ['ok', 'metadata', 'output']);
      if (
        result.ok !== true ||
        typeof result.metadata !== 'string' ||
        !(result.output instanceof Uint8Array) ||
        !(result.output.buffer instanceof ArrayBuffer) ||
        result.output.byteOffset !== 0 ||
        result.output.byteLength !== result.output.buffer.byteLength ||
        result.output.byteLength > maximumBufferedArtifactBytes
      ) {
        throw new Error();
      }
      const metadata = playbackMetadata(options, JSON.parse(result.metadata));
      worker.postMessage({ kind: 'prepared', metadata, output: result.output.buffer }, [
        result.output.buffer,
      ]);
      worker.close();
      return;
    }
    const body = object(event.data, [
      'kind',
      'request',
      'files',
      'options',
      'privateKey',
      'passphrase',
    ]);
    const request = body.request as ArtifactRequest;
    artifactFields(request);
    const options = evidenceOptions(request, body.options);
    if (
      body.kind !== 'verify' ||
      !Array.isArray(body.files) ||
      body.files.length < 1 ||
      body.files.length > 65536 ||
      !(body.privateKey instanceof ArrayBuffer) ||
      !(body.passphrase instanceof ArrayBuffer) ||
      body.privateKey.byteLength > 64 << 10 ||
      body.passphrase.byteLength > 4096
    ) {
      throw new Error();
    }
    const privateKey = new Uint8Array(body.privateKey);
    const passphrase = new Uint8Array(body.passphrase);
    buffers.push(privateKey, passphrase);
    const files = [];
    let total = 0;
    for (const item of body.files) {
      const file = object(item, ['name', 'data']);
      if (
        typeof file.name !== 'string' ||
        file.name.length > 255 ||
        !(file.data instanceof Blob) ||
        file.data.size < 1 ||
        total + file.data.size > maximumBufferedArtifactBytes
      ) {
        throw new Error();
      }
      total += file.data.size;
      const data = new Uint8Array(await file.data.arrayBuffer());
      buffers.push(data);
      files.push({ name: file.name, data });
    }
    const raw = runtime.bifroestEvidenceVerify(
      request.kind,
      request.auditlog,
      request.kind === 'recording' ? request.id : '',
      JSON.stringify(options),
      files,
      privateKey,
      passphrase,
    );
    if (raw === null || typeof raw !== 'object') {
      throw new Error();
    }
    if ('ok' in raw && raw.ok === false) {
      const failure = object(raw, ['ok', 'code']);
      failed(
        ['input', 'key', 'limit', 'verification'].includes(String(failure.code))
          ? (failure.code as EvidenceError['code'])
          : 'verification',
      );
      return;
    }
    const result = object(raw, ['ok', 'metadata', 'output']);
    if (
      result.ok !== true ||
      typeof result.metadata !== 'string' ||
      !(result.output instanceof Uint8Array) ||
      !(result.output.buffer instanceof ArrayBuffer) ||
      result.output.byteOffset !== 0 ||
      result.output.byteLength !== result.output.buffer.byteLength ||
      result.output.byteLength > maximumBufferedArtifactBytes
    ) {
      throw new Error();
    }
    const metadata = evidenceMetadata(request, options, JSON.parse(result.metadata));
    if (!options.export && result.output.byteLength !== 0) {
      throw new Error();
    }
    worker.postMessage({
      kind: 'verified',
      metadata,
      output: new Blob([result.output.buffer], { type: 'application/octet-stream' }),
    });
    worker.close();
  } catch (error) {
    failed(error instanceof EvidenceError ? error.code : 'verification');
  } finally {
    for (const value of buffers) {
      value.fill(0);
    }
  }
}

async function readBounded(
  stream: ReadableStream<Uint8Array>,
  maximum: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const reader = stream.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) {
        break;
      }
      size += next.value.byteLength;
      if (size > maximum) {
        throw new Error();
      }
      chunks.push(next.value);
    }
  } finally {
    try {
      await reader.cancel();
    } finally {
      reader.releaseLock();
    }
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

async function boot() {
  await import(/* @vite-ignore */ new URL('go-wasm-exec.js', location.href).href);
  const url = new URL('browser-evidence.wasm.gz', location.href);
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
    !['application/gzip', 'application/x-gzip'].includes(
      response.headers.get('Content-Type') ?? '',
    ) ||
    response.headers.has('Content-Encoding') ||
    response.body === null
  ) {
    throw new Error();
  }
  const compressed = await readBounded(response.body, 8 << 20);
  const bytes = await readBounded(
    new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip')),
    24 << 20,
  );
  const go = new runtime.Go();
  go.exit = () => failed('unavailable');
  const result = await WebAssembly.instantiate(bytes, go.importObject);
  void go.run(result.instance).catch(() => failed('unavailable'));
}

void boot().catch(() => failed('unavailable'));
