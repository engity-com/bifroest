import { describe, expect, it, vi } from 'vitest';
import { EvidenceError } from '../src/artifacts/evidence-protocol';
import type { ReceivedArtifact } from '../src/artifacts/protocol';
import { RecordingRuntimeOwner } from '../src/artifacts/recording-runtime-owner';
import type { RecordingRuntime } from '../src/artifacts/verify';
import { uuidText } from '../src/shared/uuid';

const firstID = '11111111-2222-4333-8444-555555555555';
const secondID = '11111111-2222-4333-8444-555555555556';
function image(source = 'default', id = firstID): ReceivedArtifact {
  return {
    request: { kind: 'recording', auditlog: source, id },
    transport: 'complete',
    evidence: 'unverified',
    metadata: { Version: 1, ID: id, ProducerID: 'a'.repeat(64), Size: 0, SHA256: 'b'.repeat(64) },
    files: [],
  };
}
function runtime() {
  let available = true;
  const value: RecordingRuntime = {
    available: () => available,
    dispose: vi.fn(() => {
      available = false;
    }),
    receive: async () => {
      throw new EvidenceError('input');
    },
    open: async () => {
      throw new EvidenceError('input');
    },
    verify: async () => {
      throw new EvidenceError('input');
    },
  };
  return value;
}
const operation = () => new AbortController().signal;

describe('actor-owned recording runtime lifetime', () => {
  it('reuses only the same source and UUID bytes, not image notation or render identity', async () => {
    const value = runtime();
    const create = vi.fn(async () => value);
    const owner = new RecordingRuntimeOwner(() => true, create);
    expect(await owner.acquire(image(), operation())).toBe(value);
    expect(await owner.acquire(image('default', uuidText(firstID)), operation())).toBe(value);
    expect(create).toHaveBeenCalledTimes(1);
    expect(value.dispose).not.toHaveBeenCalled();
    owner.dispose();
    expect(value.dispose).toHaveBeenCalledTimes(1);
  });

  it.each([image('other'), image('default', secondID)])(
    'retires a different source/recording before creating a replacement',
    async (next) => {
      const first = runtime();
      const second = runtime();
      const lifetimes: AbortSignal[] = [];
      const create = vi.fn(async (_source: string, _id: string, signal: AbortSignal) => {
        lifetimes.push(signal);
        return lifetimes.length === 1 ? first : second;
      });
      const owner = new RecordingRuntimeOwner(() => true, create);
      await owner.acquire(image(), operation());
      expect(await owner.acquire(next, operation())).toBe(second);
      expect(first.dispose).toHaveBeenCalledTimes(1);
      expect(lifetimes[0]?.aborted).toBe(true);
      expect(lifetimes[1]?.aborted).toBe(false);
      owner.dispose();
    },
  );

  it('rejects and disposes a late startup after its owner changes', async () => {
    let owns = true;
    const value = runtime();
    const started = Promise.withResolvers<RecordingRuntime>();
    const owner = new RecordingRuntimeOwner(
      () => owns,
      async () => started.promise,
    );
    const pending = owner.acquire(image(), operation());
    const rejected = expect(pending).rejects.toMatchObject({ code: 'cancelled' });
    owns = false;
    started.resolve(value);
    await rejected;
    expect(value.dispose).toHaveBeenCalledTimes(1);
    owner.dispose();
  });

  it('never revives a disposed owner, even when a startup completes later', async () => {
    const value = runtime();
    const started = Promise.withResolvers<RecordingRuntime>();
    const create = vi.fn(async () => started.promise);
    const owner = new RecordingRuntimeOwner(() => true, create);
    const pending = owner.acquire(image(), operation());
    const rejected = expect(pending).rejects.toMatchObject({ code: 'cancelled' });
    owner.dispose();
    started.resolve(value);
    await rejected;
    await expect(owner.acquire(image(), operation())).rejects.toMatchObject({ code: 'cancelled' });
    expect(value.dispose).toHaveBeenCalledTimes(1);
    expect(create).toHaveBeenCalledTimes(1);
  });

  it('does not let an older startup replace a newer recording', async () => {
    const old = runtime();
    const current = runtime();
    const started = Promise.withResolvers<RecordingRuntime>();
    const create = vi.fn(async (_source: string, id: string) =>
      id === firstID ? started.promise : current,
    );
    const owner = new RecordingRuntimeOwner(() => true, create);
    const pending = owner.acquire(image(), operation());
    const rejected = expect(pending).rejects.toMatchObject({ code: 'cancelled' });
    expect(await owner.acquire(image('default', secondID), operation())).toBe(current);
    started.resolve(old);
    await rejected;
    expect(old.dispose).toHaveBeenCalledTimes(1);
    expect(current.dispose).not.toHaveBeenCalled();
    expect(await owner.acquire(image('default', secondID), operation())).toBe(current);
    owner.dispose();
  });

  it('preserves startup failure without automatic retry and aborts its lifetime', async () => {
    const failure = new EvidenceError('worker');
    const lifetimes: AbortSignal[] = [];
    const create = vi.fn(
      async (_source: string, _id: string, signal: AbortSignal): Promise<RecordingRuntime> => {
        lifetimes.push(signal);
        throw failure;
      },
    );
    const owner = new RecordingRuntimeOwner(() => true, create);
    await expect(owner.acquire(image(), operation())).rejects.toBe(failure);
    expect(create).toHaveBeenCalledTimes(1);
    expect(lifetimes[0]?.aborted).toBe(true);
    owner.dispose();
  });

  it('does not create a worker for an aborted request or an obsolete owner', async () => {
    const create = vi.fn(async () => runtime());
    const stopped = new AbortController();
    stopped.abort();
    const owner = new RecordingRuntimeOwner(() => true, create);
    await expect(owner.acquire(image(), stopped.signal)).rejects.toMatchObject({
      code: 'cancelled',
    });
    const obsolete = new RecordingRuntimeOwner(() => false, create);
    await expect(obsolete.acquire(image(), operation())).rejects.toMatchObject({
      code: 'cancelled',
    });
    expect(create).not.toHaveBeenCalled();
  });
});
