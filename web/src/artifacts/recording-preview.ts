import { uuidEqual } from '../shared/uuid';
import type { ArtifactSessionSecrets } from './artifact-secrets';
import { EvidenceError } from './evidence-protocol';
import type { RecordingInfo } from './open-recording';
import type { PlaybackImage } from './playback-protocol';
import type { ReceivedArtifact } from './protocol';
import type { EvidenceKey, RecordingRuntime } from './verify';

export type RecordingPreview =
  | { readonly kind: 'key-required'; readonly info: RecordingInfo }
  | { readonly kind: 'metadata'; readonly info: RecordingInfo }
  | {
      readonly kind: 'ready';
      readonly info: RecordingInfo;
      readonly source: Blob;
      readonly image: PlaybackImage;
    };

export interface RecordingPreviewContext {
  readonly signal: AbortSignal;
  current(): boolean;
  target(): { readonly flow?: string; readonly sessionId?: string } | null;
  readonly keys: Pick<ArtifactSessionSecrets, 'matching' | 'rememberDecryption'>;
  information(info: RecordingInfo): void;
  keyRemembered(): void;
}

// Decode-only use case. No React state, server request, signature verification
// or automatic playback is available through these ports. A ready image is
// transferred to the caller, which must publish it only to its still-current owner.
export async function prepareRecordingPreview(
  runtime: Pick<RecordingRuntime, 'open'>,
  artifact: ReceivedArtifact,
  key: EvidenceKey | null,
  context: RecordingPreviewContext,
): Promise<RecordingPreview | null> {
  const current = () => !context.signal.aborted && context.current();
  if (!current()) {
    return null;
  }
  if (artifact.request.kind !== 'recording') {
    throw new EvidenceError('input');
  }
  let result = await runtime.open(artifact, key, context.signal);
  if (!current()) {
    result.image?.dispose();
    return null;
  }
  context.information(result.info);
  if (!current()) {
    result.image?.dispose();
    return null;
  }
  if (result.info.requiresKey) {
    const cached = context.keys.matching(result.info.recipient);
    if (!current()) {
      result.image?.dispose();
      return null;
    }
    if (!cached) {
      return { kind: 'key-required', info: result.info };
    }
    key = cached;
    result = await runtime.open(artifact, key, context.signal);
  }
  if (!current()) {
    result.image?.dispose();
    return null;
  }
  context.information(result.info);
  if (!current()) {
    result.image?.dispose();
    return null;
  }
  if (!result.image) {
    return { kind: 'metadata', info: result.info };
  }
  try {
    const target = context.target();
    if (
      (target?.flow && target.flow !== result.info.flow) ||
      (target?.sessionId && !uuidEqual(target.sessionId, result.info.sessionId))
    ) {
      throw new EvidenceError('input');
    }
    if (key && result.info.decryption === 'authenticated') {
      context.keys.rememberDecryption(key, result.info);
      context.keyRemembered();
    }
    const source = artifact.files[0]?.data;
    if (!source) {
      throw new EvidenceError('input');
    }
    return { kind: 'ready', info: result.info, source, image: result.image };
  } catch (error) {
    result.image.dispose();
    throw error;
  }
}
