import { afterEach, describe, expect, it, vi } from 'vitest';
import { EvidenceError } from '../src/artifacts/evidence-protocol';
import type { RecordingInfo } from '../src/artifacts/open-recording';
import type { PlaybackImage } from '../src/artifacts/playback-protocol';
import type { ReceivedArtifact } from '../src/artifacts/protocol';
import {
  prepareRecordingPreview,
  type RecordingPreviewContext,
} from '../src/artifacts/recording-preview';
import type { EvidenceKey } from '../src/artifacts/verify';
import { uuidText } from '../src/shared/uuid';
import { openedFixture } from './open-recording-fixture';

const id = '11111111-2222-4333-8444-555555555555';
const other = '11111111-2222-4333-8444-555555555556';
const source = new Blob(['owned recording source']);
const key: EvidenceKey = { file: new Blob(['local key']), passphrase: 'local test secret' };
const images: PlaybackImage[] = [];

function artifact(): ReceivedArtifact {
  return {
    request: { kind: 'recording', auditlog: 'default', id },
    transport: 'complete',
    evidence: 'unverified',
    metadata: {
      Version: 1,
      ID: id,
      ProducerID: 'a'.repeat(64),
      Size: source.size,
      SHA256: 'b'.repeat(64),
    },
    files: [{ name: 'recording', data: source }],
  };
}
function opened(extra: Partial<RecordingInfo> = {}) {
  const result = openedFixture(id, 'a'.repeat(64), extra);
  if (result.image) {
    vi.spyOn(result.image, 'dispose');
    images.push(result.image);
  }
  return result;
}
function context() {
  return {
    signal: new AbortController().signal,
    current: vi.fn(() => true),
    target: vi.fn((): ReturnType<RecordingPreviewContext['target']> => null),
    keys: {
      matching: vi.fn((_recipient: string): EvidenceKey | null => null),
      rememberDecryption: vi.fn(),
    },
    information: vi.fn(),
    keyRemembered: vi.fn(),
  } satisfies RecordingPreviewContext;
}
function runtime(value = opened()) {
  return {
    open: vi.fn(
      async (_artifact: ReceivedArtifact, _key: EvidenceKey | null, _signal: AbortSignal) => value,
    ),
    verify: vi.fn(),
  };
}
afterEach(() => {
  for (const image of images.splice(0)) {
    image.dispose();
  }
  vi.restoreAllMocks();
});

describe('explicit recording preview preparation', () => {
  it('transfers the original local bytes and decoded image without verifying or caching a key', async () => {
    const value = opened();
    const reader = runtime(value);
    const owner = context();
    const result = await prepareRecordingPreview(reader, artifact(), null, owner);
    expect(result).toEqual({ kind: 'ready', info: value.info, source, image: value.image });
    expect(owner.information.mock.calls.map(([info]) => info)).toEqual([value.info, value.info]);
    expect(reader.open).toHaveBeenCalledTimes(1);
    expect(reader.verify).not.toHaveBeenCalled();
    expect(owner.keys.matching).not.toHaveBeenCalled();
    expect(owner.keys.rememberDecryption).not.toHaveBeenCalled();
    expect(value.image?.dispose).not.toHaveBeenCalled();
  });

  it('reports a missing local key without starting another decode or verification', async () => {
    const locked = opened({
      encrypted: true,
      requiresKey: true,
      recipient: 'SHA256:recipient',
      decryption: 'not-checked',
    });
    const reader = runtime(locked);
    const owner = context();
    expect(await prepareRecordingPreview(reader, artifact(), null, owner)).toEqual({
      kind: 'key-required',
      info: locked.info,
    });
    expect(reader.open).toHaveBeenCalledTimes(1);
    expect(reader.verify).not.toHaveBeenCalled();
    expect(owner.information).toHaveBeenCalledTimes(1);
    expect(owner.keys.matching).toHaveBeenCalledWith(locked.info.recipient);
  });

  it('uses only a matching approved local key and remembers only authenticated decryption', async () => {
    const locked = opened({
      encrypted: true,
      requiresKey: true,
      recipient: 'SHA256:recipient',
      decryption: 'not-checked',
    });
    const unlocked = opened({
      encrypted: true,
      recipient: locked.info.recipient,
      decryption: 'authenticated',
    });
    const reader = runtime(locked);
    reader.open.mockResolvedValueOnce(locked).mockResolvedValueOnce(unlocked);
    const owner = context();
    owner.keys.matching.mockReturnValue(key);
    const input = artifact();
    expect((await prepareRecordingPreview(reader, input, null, owner))?.kind).toBe('ready');
    expect(reader.open).toHaveBeenNthCalledWith(2, input, key, owner.signal);
    expect(owner.keys.rememberDecryption).toHaveBeenCalledExactlyOnceWith(key, unlocked.info);
    expect(owner.keyRemembered).toHaveBeenCalledTimes(1);
    expect(reader.verify).not.toHaveBeenCalled();
  });

  it('compares the selected session by UUID bytes, not text notation', async () => {
    const reader = runtime(opened({ sessionId: id }));
    const owner = context();
    owner.target.mockReturnValue({ flow: 'docker', sessionId: uuidText(id) });
    expect((await prepareRecordingPreview(reader, artifact(), null, owner))?.kind).toBe('ready');
  });

  it.each([{ flow: 'other' }, { sessionId: other }])(
    'rejects an unmatched current selector and disposes private output',
    async (target) => {
      const value = opened({ sessionId: id });
      const owner = context();
      owner.target.mockReturnValue(target);
      await expect(
        prepareRecordingPreview(runtime(value), artifact(), key, owner),
      ).rejects.toMatchObject({ code: 'input' });
      expect(value.image?.dispose).toHaveBeenCalledTimes(1);
      expect(owner.keys.rememberDecryption).not.toHaveBeenCalled();
    },
  );

  it('does not start a decode for an already aborted operation or obsolete owner', async () => {
    const reader = runtime();
    const owner = context();
    const stopped = new AbortController();
    stopped.abort();
    expect(
      await prepareRecordingPreview(reader, artifact(), null, { ...owner, signal: stopped.signal }),
    ).toBeNull();
    owner.current.mockReturnValue(false);
    expect(await prepareRecordingPreview(reader, artifact(), null, owner)).toBeNull();
    expect(reader.open).not.toHaveBeenCalled();
  });

  it.each(['owner', 'abort'])(
    'disposes a late image after %s retirement without publishing metadata',
    async (reason) => {
      const value = opened();
      const pending = Promise.withResolvers<typeof value>();
      const reader = runtime(value);
      reader.open.mockImplementationOnce(() => pending.promise);
      const owner = context();
      const stopped = new AbortController();
      const result = prepareRecordingPreview(reader, artifact(), null, {
        ...owner,
        signal: stopped.signal,
      });
      if (reason === 'owner') {
        owner.current.mockReturnValue(false);
      } else {
        stopped.abort();
      }
      pending.resolve(value);
      expect(await result).toBeNull();
      expect(value.image?.dispose).toHaveBeenCalledTimes(1);
      expect(owner.information).not.toHaveBeenCalled();
      expect(owner.keys.rememberDecryption).not.toHaveBeenCalled();
    },
  );

  it('checks ownership again after decoding with a cached key', async () => {
    const locked = opened({
      encrypted: true,
      requiresKey: true,
      recipient: 'SHA256:recipient',
      decryption: 'not-checked',
    });
    const unlocked = opened({ encrypted: true, decryption: 'authenticated' });
    const reader = runtime(locked);
    const owner = context();
    owner.keys.matching.mockReturnValue(key);
    reader.open.mockResolvedValueOnce(locked).mockImplementationOnce(async () => {
      owner.current.mockReturnValue(false);
      return unlocked;
    });
    expect(await prepareRecordingPreview(reader, artifact(), null, owner)).toBeNull();
    expect(unlocked.image?.dispose).toHaveBeenCalledTimes(1);
    expect(owner.information).toHaveBeenCalledTimes(1);
    expect(owner.keys.rememberDecryption).not.toHaveBeenCalled();
  });

  it.each(['information', 'key-lookup'])(
    'does not continue private work when %s retires the owner',
    async (stage) => {
      const locked = opened({
        encrypted: true,
        requiresKey: true,
        recipient: 'SHA256:recipient',
        decryption: 'not-checked',
      });
      const reader = runtime(locked);
      const owner = context();
      if (stage === 'information') {
        owner.information.mockImplementationOnce(() => {
          owner.current.mockReturnValue(false);
        });
      } else {
        owner.keys.matching.mockImplementationOnce(() => {
          owner.current.mockReturnValue(false);
          return key;
        });
      }
      expect(await prepareRecordingPreview(reader, artifact(), null, owner)).toBeNull();
      expect(reader.open).toHaveBeenCalledTimes(1);
      expect(owner.keys.rememberDecryption).not.toHaveBeenCalled();
    },
  );

  it('disposes unpublished plaintext if remembering the authenticated key fails', async () => {
    const value = opened({ encrypted: true, decryption: 'authenticated' });
    const owner = context();
    const failure = new EvidenceError('cancelled');
    owner.keys.rememberDecryption.mockImplementation(() => {
      throw failure;
    });
    await expect(prepareRecordingPreview(runtime(value), artifact(), key, owner)).rejects.toBe(
      failure,
    );
    expect(value.image?.dispose).toHaveBeenCalledTimes(1);
    expect(owner.keyRemembered).not.toHaveBeenCalled();
  });

  it('keeps decoder failures unchanged and never retries them', async () => {
    const reader = runtime();
    const failure = new EvidenceError('key');
    reader.open.mockRejectedValueOnce(failure);
    await expect(prepareRecordingPreview(reader, artifact(), key, context())).rejects.toBe(failure);
    expect(reader.open).toHaveBeenCalledTimes(1);
    expect(reader.verify).not.toHaveBeenCalled();
  });

  it('rejects a non-recording request before using the decode port', async () => {
    const reader = runtime();
    await expect(
      prepareRecordingPreview(
        reader,
        { ...artifact(), request: { kind: 'audit', auditlog: 'default' } },
        null,
        context(),
      ),
    ).rejects.toMatchObject({ code: 'input' });
    expect(reader.open).not.toHaveBeenCalled();
  });
});
