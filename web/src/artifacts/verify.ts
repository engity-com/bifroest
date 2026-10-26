import { object } from '../remember/http';
import { RememberMeError } from '../remember/protocol';
import { readLocalBytes } from '../wasm/local-file';
import type { EvidenceOptions, VerifiedArtifact } from './evidence-protocol';
import { EvidenceError, evidenceMetadata, evidenceOptions } from './evidence-protocol';
import { expectedFiles, transferMetadata } from './metadata';
import type { ArtifactRequest, ReceivedArtifact } from './protocol';
import { artifactFields, maximumBufferedArtifactBytes } from './protocol';

export interface EvidenceKey {
  readonly file: File;
  readonly passphrase: string;
}

export function evidenceRPC(
  worker: Worker,
  kind: 'ready' | 'verified' | 'prepared',
  signal: AbortSignal,
  input?: unknown,
  transfer: Transferable[] = [],
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      worker.removeEventListener('message', received);
      worker.removeEventListener('error', failed);
      worker.removeEventListener('messageerror', failed);
      signal.removeEventListener('abort', aborted);
    };
    const failed = (event?: Event) => {
      event?.preventDefault();
      cleanup();
      reject(new EvidenceError('unavailable'));
    };
    const aborted = () => {
      cleanup();
      reject(new EvidenceError('cancelled'));
    };
    const received = (event: MessageEvent) => {
      try {
        if (event.data?.kind === 'failed') {
          const body = object(event.data, ['kind', 'code']);
          if (
            !['input', 'key', 'limit', 'verification', 'unavailable'].includes(String(body.code))
          ) {
            throw new Error();
          }
          cleanup();
          reject(new EvidenceError(body.code as EvidenceError['code']));
          return;
        }
        const body = object(
          event.data,
          kind === 'ready' ? ['kind'] : ['kind', 'metadata', 'output'],
        );
        if (body.kind !== kind || signal.aborted) {
          throw new Error();
        }
        cleanup();
        resolve(body);
      } catch {
        failed();
      }
    };
    worker.addEventListener('message', received);
    worker.addEventListener('error', failed);
    worker.addEventListener('messageerror', failed);
    signal.addEventListener('abort', aborted, { once: true });
    if (signal.aborted) {
      aborted();
      return;
    }
    try {
      if (input !== undefined) {
        worker.postMessage(input, transfer);
      }
    } catch {
      failed();
    }
  });
}

// Only immutable completed transport Blobs and local key bytes enter this owned
// worker. No bearer, URL or server operation is accepted by the evidence RPC.
export async function verifyArtifact(
  artifact: ReceivedArtifact,
  requested: EvidenceOptions,
  key: EvidenceKey | null,
  signal: AbortSignal,
): Promise<VerifiedArtifact> {
  let request: ArtifactRequest;
  let files: ReceivedArtifact['files'];
  let options: EvidenceOptions;
  try {
    const value = object(artifact, ['request', 'transport', 'evidence', 'metadata', 'files']);
    request = Object.freeze({ ...artifact.request }) as ArtifactRequest;
    artifactFields(request);
    options = evidenceOptions(request, requested);
    if (
      value.transport !== 'complete' ||
      value.evidence !== 'unverified' ||
      !Array.isArray(value.files)
    ) {
      throw new Error();
    }
    const metadata = transferMetadata(request, value.metadata);
    const expected = expectedFiles(metadata);
    if (expected.length !== value.files.length) {
      throw new Error();
    }
    let total = 0;
    files = Object.freeze(
      value.files.map((entry, index) => {
        const file = object(entry, ['name', 'data']);
        const wanted = expected[index];
        if (
          wanted === undefined ||
          file.name !== wanted.name ||
          !(file.data instanceof Blob) ||
          file.data.size !== wanted.size
        ) {
          throw new Error();
        }
        total += file.data.size;
        if (total > maximumBufferedArtifactBytes) {
          throw new Error();
        }
        return Object.freeze({ name: wanted.name, data: file.data });
      }),
    );
    if (
      key !== null &&
      (options.level !== 'private' ||
        options.recipient === '' ||
        key.file.size < 1 ||
        key.file.size > 64 << 10 ||
        key.passphrase.length > 4096 ||
        !key.passphrase.isWellFormed())
    ) {
      throw new Error();
    }
  } catch (error) {
    throw error instanceof EvidenceError ? error : new EvidenceError('input');
  }
  const lifetime = AbortSignal.timeout(120_000);
  const stopped = AbortSignal.any([signal, lifetime]);
  if (stopped.aborted) {
    throw new EvidenceError('cancelled');
  }
  let privateBytes: ArrayBuffer | undefined;
  const password = new TextEncoder().encode(key?.passphrase ?? '');
  if (password.byteLength > 4096) {
    password.fill(0);
    throw new EvidenceError('key');
  }
  let worker: Worker | undefined;
  const terminate = () => worker?.terminate();
  stopped.addEventListener('abort', terminate, { once: true });
  try {
    worker = new Worker('/_bifroest/files/browser-evidence-worker.js', {
      type: 'module',
      credentials: 'omit',
      name: 'bifroest-evidence',
    });
    await evidenceRPC(worker, 'ready', AbortSignal.any([stopped, AbortSignal.timeout(20_000)]));
    if (stopped.aborted) {
      throw new EvidenceError('cancelled');
    }
    privateBytes = key === null ? new ArrayBuffer(0) : await readLocalBytes(key.file, stopped);
    if (privateBytes.byteLength > 64 << 10 || stopped.aborted) {
      throw new EvidenceError('key');
    }
    const result = await evidenceRPC(
      worker,
      'verified',
      stopped,
      {
        kind: 'verify',
        request,
        files,
        options,
        privateKey: privateBytes,
        passphrase: password.buffer,
      },
      [privateBytes, password.buffer],
    );
    const metadata = evidenceMetadata(request, options, result.metadata);
    if (
      !(result.output instanceof Blob) ||
      result.output.size > maximumBufferedArtifactBytes ||
      (!options.export && result.output.size !== 0)
    ) {
      throw new EvidenceError('verification');
    }
    if (stopped.aborted) {
      throw new EvidenceError('cancelled');
    }
    return Object.freeze({
      request,
      provenance: 'bytes-only',
      metadata,
      output: options.export ? result.output : null,
    });
  } catch (error) {
    if (signal.aborted) {
      throw new EvidenceError('cancelled');
    }
    if (lifetime.aborted) {
      throw new EvidenceError('unavailable');
    }
    if (error instanceof RememberMeError && error.code === 'key-import') {
      throw new EvidenceError('key');
    }
    if (error instanceof EvidenceError && error.code !== 'cancelled') {
      throw error;
    }
    throw new EvidenceError('unavailable');
  } finally {
    stopped.removeEventListener('abort', terminate);
    worker?.terminate();
    if (privateBytes?.byteLength) {
      new Uint8Array(privateBytes).fill(0);
    }
    if (password.byteLength) {
      password.fill(0);
    }
  }
}
