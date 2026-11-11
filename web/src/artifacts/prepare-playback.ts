import { EvidenceError } from './evidence-protocol';
import type { PlaybackOptions } from './playback-protocol';
import { PlaybackImage, playbackOptions } from './playback-protocol';
import { maximumBufferedArtifactBytes } from './protocol';
import { evidenceRPC } from './verify';

// Only an immutable local Cast Blob and independent expectations enter this
// fresh one-shot worker. No key, bearer, URL or server action exists in this RPC.
export async function prepareRecordingPlayback(
  source: Blob,
  expected: PlaybackOptions,
  signal: AbortSignal,
): Promise<PlaybackImage> {
  const options = playbackOptions(expected);
  if (!(source instanceof Blob) || source.size < 1 || source.size > maximumBufferedArtifactBytes) {
    throw new EvidenceError('limit');
  }
  const lifetime = AbortSignal.timeout(120_000);
  const stopped = AbortSignal.any([signal, lifetime]);
  if (stopped.aborted) {
    throw new EvidenceError('cancelled');
  }
  let worker: Worker | undefined;
  const terminate = () => worker?.terminate();
  stopped.addEventListener('abort', terminate, { once: true });
  try {
    worker = new Worker('/_bifroest/files/browser-evidence-worker.js', {
      type: 'module',
      credentials: 'omit',
      name: 'bifroest-playback',
    });
    await evidenceRPC(worker, 'ready', AbortSignal.any([stopped, AbortSignal.timeout(20_000)]));
    const reply = await evidenceRPC(worker, 'prepared', stopped, {
      kind: 'playback',
      options,
      data: source,
    });
    if (!(reply.output instanceof ArrayBuffer)) {
      throw new EvidenceError('verification');
    }
    const image = new PlaybackImage(options, reply.metadata, reply.output);
    if (stopped.aborted) {
      image.dispose();
      throw new EvidenceError('cancelled');
    }
    return image;
  } catch (error) {
    if (signal.aborted) {
      throw new EvidenceError('cancelled');
    }
    if (lifetime.aborted) {
      throw new EvidenceError('unavailable');
    }
    if (error instanceof EvidenceError && error.code !== 'cancelled') {
      throw error;
    }
    throw new EvidenceError('unavailable');
  } finally {
    stopped.removeEventListener('abort', terminate);
    worker?.terminate();
  }
}
