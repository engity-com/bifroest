import type { ArtifactResponseImage } from '../remember/http';
import { object } from '../remember/http';
import { RememberMeError } from '../remember/protocol';
import { expectedFiles, transferMetadata } from './metadata';
import type { ArtifactRequest, ReceivedArtifact } from './protocol';
import { artifactFields } from './protocol';

function message(
  worker: Worker,
  kind: 'ready' | 'received',
  signal: AbortSignal,
  request?: unknown,
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
      reject(new RememberMeError('unavailable'));
    };
    const aborted = () => {
      cleanup();
      reject(new RememberMeError(signal.aborted ? 'cancelled' : 'unavailable'));
    };
    const received = (event: MessageEvent) => {
      try {
        if (event.data?.kind === 'failed') {
          const body = object(event.data, ['kind', 'reason']);
          cleanup();
          reject(
            new RememberMeError(body.reason === 'too-large' ? 'artifact-too-large' : 'unavailable'),
          );
          return;
        }
        const body = object(
          event.data,
          kind === 'ready' ? ['kind'] : ['kind', 'metadata', 'files'],
        );
        if (body.kind !== kind || stopped.aborted) {
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

// No bearer enters this worker. No body or Blob is exposed before the native Go
// receiver has accepted selectors, data-end, post-driver completion and raw EOF.
export async function receiveArtifact(
  request: ArtifactRequest,
  open: (signal: AbortSignal) => Promise<ArtifactResponseImage>,
  signal: AbortSignal,
): Promise<ReceivedArtifact> {
  const selected = Object.freeze({ ...request }) as ArtifactRequest;
  artifactFields(selected);
  const stopped = AbortSignal.any([signal, AbortSignal.timeout(120_000)]);
  if (stopped.aborted) {
    throw new RememberMeError('cancelled');
  }
  const worker = new Worker('/_bifroest/files/browser-transfer-worker.js', {
    type: 'module',
    credentials: 'omit',
    name: 'bifroest-transfer',
  });
  const terminate = () => worker.terminate();
  stopped.addEventListener('abort', terminate, { once: true });
  let image: ArtifactResponseImage | undefined;
  try {
    await message(worker, 'ready', stopped);
    if (stopped.aborted) {
      throw new RememberMeError('cancelled');
    }
    image = await open(stopped);
    if (stopped.aborted) {
      throw new RememberMeError('cancelled');
    }
    const result = await message(
      worker,
      'received',
      stopped,
      { kind: 'receive', request: selected, ...image },
      [image.bytes],
    );
    const metadata = transferMetadata(selected, result.metadata);
    const expected = expectedFiles(metadata);
    if (!Array.isArray(result.files) || result.files.length !== expected.length) {
      throw new RememberMeError('unavailable');
    }
    const files = result.files.map((value, index) => {
      const file = object(value, ['name', 'data']);
      const entry = expected[index];
      if (
        entry === undefined ||
        file.name !== entry.name ||
        !(file.data instanceof Blob) ||
        file.data.size !== entry.size
      ) {
        throw new RememberMeError('unavailable');
      }
      return Object.freeze({ name: entry.name, data: file.data });
    });
    if (stopped.aborted) {
      throw new RememberMeError('cancelled');
    }
    return Object.freeze({
      request: selected,
      transport: 'complete',
      evidence: 'unverified',
      metadata,
      files: Object.freeze(files),
    });
  } catch (error) {
    if (signal.aborted) {
      throw new RememberMeError('cancelled');
    }
    throw error instanceof RememberMeError ? error : new RememberMeError('unavailable');
  } finally {
    stopped.removeEventListener('abort', terminate);
    worker.terminate();
    if (image?.bytes.byteLength) {
      new Uint8Array(image.bytes).fill(0);
    }
  }
}
