import type { RecordingInfo } from '../src/artifacts/open-recording';
import { PlaybackImage } from '../src/artifacts/playback-protocol';

export function openedFixture(
  id: string,
  producer = 'a'.repeat(64),
  extra: Partial<RecordingInfo> = {},
) {
  const info: RecordingInfo = {
    recordingId: id,
    producer,
    encrypted: false,
    recipient: '',
    requiresKey: false,
    decryption: 'not-encrypted',
    flow: 'docker',
    sessionId: '',
    ...extra,
  };
  return {
    info,
    image: info.requiresKey
      ? null
      : new PlaybackImage(
          { id, producer: '', allowUntrusted: true, unchecked: true },
          {
            version: 1,
            recordingId: id,
            producer,
            trust: 'not-checked',
            columns: 80,
            rows: 24,
            pty: false,
            frames: 0,
            durationUs: 0,
            status: 'completed',
            exitStatus: 0,
          },
          new ArrayBuffer(0),
        ),
  };
}
