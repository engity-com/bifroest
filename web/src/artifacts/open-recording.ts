import { object } from '../remember/http';
import { resourceID, uuidEqual } from '../shared/uuid';
import { readLocalBytes } from '../wasm/local-file';
import { EvidenceError } from './evidence-protocol';
import { evidenceRPC } from './evidence-rpc';
import { transferMetadata } from './metadata';
import { PlaybackImage } from './playback-protocol';
import type { ReceivedArtifact } from './protocol';
import { artifactFields, maximumBufferedArtifactBytes } from './protocol';
import type { EvidenceKey } from './verify';

export interface RecordingInfo {
  readonly recordingId: string;
  readonly producer: string;
  readonly recipient: string;
  readonly encrypted: boolean;
  readonly requiresKey: boolean;
  readonly decryption: 'not-checked' | 'not-encrypted' | 'authenticated';
  readonly flow: string;
  readonly sessionId: string;
}
// Decode only. Neither this RPC nor its result represents a signature check.
export async function openRecording(
  image: ReceivedArtifact,
  key: EvidenceKey | null,
  signal: AbortSignal,
): Promise<{ info: RecordingInfo; image: PlaybackImage | null }> {
  return openRecordingWithWorker(image, key, signal);
}

export async function openRecordingWithWorker(
  image: ReceivedArtifact,
  key: EvidenceKey | null,
  signal: AbortSignal,
  existing?: Worker,
): Promise<{ info: RecordingInfo; image: PlaybackImage | null }> {
  if (signal.aborted) {
    throw new EvidenceError('cancelled');
  }
  if (
    image.request.kind !== 'recording' ||
    image.files.length !== 1 ||
    image.files[0]?.name !== 'recording'
  ) {
    throw new EvidenceError('input');
  }
  const request = { ...image.request };
  const source = image.files[0].data;
  artifactFields(request);
  const transport = transferMetadata(request, image.metadata);
  if (
    image.transport !== 'complete' ||
    image.evidence !== 'unverified' ||
    !(source instanceof Blob) ||
    !('Size' in transport) ||
    source.size !== transport.Size ||
    source.size < 1 ||
    source.size > maximumBufferedArtifactBytes
  ) {
    throw new EvidenceError('input');
  }
  if (
    key &&
    (key.file.size < 1 ||
      key.file.size > 64 << 10 ||
      key.passphrase.length > 4096 ||
      !key.passphrase.isWellFormed())
  ) {
    throw new EvidenceError('key');
  }
  let worker: Worker;
  try {
    worker =
      existing ??
      new Worker('/_bifroest/files/browser-evidence-worker.js', {
        type: 'module',
        credentials: 'omit',
        name: 'bifroest-recording-open',
      });
  } catch {
    throw new EvidenceError('worker');
  }
  const stop = () => worker.terminate();
  signal.addEventListener('abort', stop, { once: true });
  const password = new TextEncoder().encode(key?.passphrase ?? '');
  let privateBytes: ArrayBuffer | undefined;
  try {
    if (!existing) {
      await evidenceRPC(worker, 'ready', AbortSignal.any([signal, AbortSignal.timeout(20_000)]));
    }
    privateBytes = key ? await readLocalBytes(key.file, signal) : new ArrayBuffer(0);
    if (privateBytes.byteLength > 64 << 10 || password.byteLength > 4096) {
      throw new EvidenceError('key');
    }
    const reply = await evidenceRPC(
      worker,
      'opened',
      signal,
      {
        kind: 'open-recording',
        id: request.id,
        data: source,
        privateKey: privateBytes,
        passphrase: password.buffer,
      },
      [privateBytes, password.buffer],
    );
    const body = object(reply.metadata, ['info', 'playback']);
    const info = object(body.info, [
      'recordingId',
      'producer',
      'recipient',
      'encrypted',
      'requiresKey',
      'decryption',
      'flow',
      'sessionId',
    ]);
    if (
      !uuidEqual(info.recordingId, request.id) ||
      typeof info.producer !== 'string' ||
      !/^[0-9a-f]{64}$/u.test(info.producer) ||
      /^0+$/u.test(info.producer) ||
      typeof info.recipient !== 'string' ||
      (info.recipient !== '' && !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(info.recipient)) ||
      typeof info.encrypted !== 'boolean' ||
      info.encrypted !== (info.recipient !== '') ||
      typeof info.requiresKey !== 'boolean' ||
      typeof info.flow !== 'string' ||
      info.flow.length > 255 ||
      typeof info.sessionId !== 'string' ||
      (info.sessionId !== '' && !resourceID(info.sessionId)) ||
      !['not-checked', 'not-encrypted', 'authenticated'].includes(String(info.decryption)) ||
      !(reply.output instanceof ArrayBuffer)
    ) {
      throw new EvidenceError('input');
    }
    const metadata = info as unknown as RecordingInfo;
    if (metadata.requiresKey) {
      if (
        !metadata.encrypted ||
        key !== null ||
        metadata.decryption !== 'not-checked' ||
        body.playback !== null ||
        info.flow !== '' ||
        info.sessionId !== '' ||
        reply.output.byteLength !== 0
      ) {
        throw new EvidenceError('input');
      }
      return { info: metadata, image: null };
    }
    if (metadata.decryption !== (metadata.encrypted ? 'authenticated' : 'not-encrypted')) {
      throw new EvidenceError('input');
    }
    try {
      return {
        info: metadata,
        image: new PlaybackImage(
          { id: request.id, producer: '', allowUntrusted: true, unchecked: true },
          body.playback,
          reply.output,
        ),
      };
    } catch {
      throw new EvidenceError('protocol');
    }
  } finally {
    if (privateBytes?.byteLength) {
      new Uint8Array(privateBytes).fill(0);
    }
    if (password.byteLength) {
      password.fill(0);
    }
    signal.removeEventListener('abort', stop);
    if (!existing) {
      worker.terminate();
    }
  }
}
