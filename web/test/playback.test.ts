import { afterEach, describe, expect, it, vi } from 'vitest';
import { RecordingPlayback } from '../src/artifacts/playback';
import type { PlaybackMetadata, PlaybackOptions } from '../src/artifacts/playback-protocol';
import { PlaybackImage } from '../src/artifacts/playback-protocol';
import { prepareRecordingPlayback } from '../src/artifacts/prepare-playback';
import { required } from './required';

const options: PlaybackOptions = {
  id: '34e34ab8-7457-4d88-a5e4-c57791775c3a',
  producer: 'a'.repeat(64),
  allowUntrusted: false,
};
const metadata: PlaybackMetadata = {
  version: 1,
  recordingId: options.id,
  producer: options.producer,
  trust: 'pinned',
  columns: 80,
  rows: 24,
  pty: true,
  frames: 2,
  durationUs: 300_000,
  status: 'completed',
  exitStatus: 7,
};
function wire(frames: { atUs: number; kind: number; data: Uint8Array }[]): ArrayBuffer {
  const bytes = new Uint8Array(frames.reduce((total, frame) => total + 13 + frame.data.length, 0));
  const view = new DataView(bytes.buffer);
  let offset = 0;
  for (const frame of frames) {
    view.setBigUint64(offset, BigInt(frame.atUs), true);
    view.setUint8(offset + 8, frame.kind);
    view.setUint32(offset + 9, frame.data.length, true);
    bytes.set(frame.data, offset + 13);
    offset += 13 + frame.data.length;
  }
  return bytes.buffer;
}
function image() {
  return new PlaybackImage(
    options,
    metadata,
    wire([
      { atUs: 0, kind: 0, data: new Uint8Array([0xff, 65]) },
      { atUs: 200_000, kind: 0, data: new Uint8Array([66]) },
    ]),
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('local playback transport/scheduler (not a Cast verifier)', () => {
  it('takes exclusive image ownership, preserves raw bytes and rejects malformed wire without a partial plan', () => {
    const raw = wire([{ atUs: 0, kind: 0, data: new Uint8Array([0xff]) }]);
    const plan = new PlaybackImage(options, { ...metadata, frames: 1 }, raw);
    expect(raw.byteLength).toBe(0);
    const frame = plan.frame(0);
    if (frame.kind === 3) {
      throw new Error('unexpected fixture kind');
    }
    expect([...frame.data]).toEqual([0xff]);
    frame.data.fill(0);
    const second = plan.frame(0);
    if (second.kind === 3) {
      throw new Error('unexpected fixture kind');
    }
    expect([...second.data]).toEqual([0xff]);
    plan.dispose();
    expect(() => plan.frame(0)).toThrow();
    for (const [info, bytes] of [
      [
        { ...metadata, frames: 1, columns: 513 },
        wire([{ atUs: 0, kind: 0, data: new Uint8Array([1]) }]),
      ],
      [
        { ...metadata, frames: 1, trust: 'untrusted' },
        wire([{ atUs: 0, kind: 0, data: new Uint8Array([1]) }]),
      ],
      [{ ...metadata, frames: 1 }, wire([{ atUs: 0, kind: 4, data: new Uint8Array([1]) }])],
      [{ ...metadata, frames: 1 }, wire([{ atUs: 900_000, kind: 0, data: new Uint8Array([1]) }])],
      [{ ...metadata, frames: 1 }, new ArrayBuffer(12)],
      [{ ...metadata, frames: 0 }, new ArrayBuffer(1)],
    ] as const) {
      expect(() => new PlaybackImage(options, info, bytes)).toThrow();
    }
  });

  it('starts paused, uses monotonic local timing/speed and never calls an execution transport', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const received: number[][] = [];
    const states: string[] = [];
    const reset = vi.fn();
    const playback = new RecordingPlayback(
      image(),
      {
        reset,
        resize() {},
        write: (data, done) => {
          received.push([...data]);
          done();
        },
      },
      (state) => states.push(state.phase),
    );
    expect(states).toEqual(['paused']);
    expect(received).toEqual([]);
    playback.play();
    await vi.advanceTimersByTimeAsync(100);
    expect(received).toEqual([[0xff, 65]]);
    playback.pause();
    await vi.advanceTimersByTimeAsync(1000);
    expect(received).toHaveLength(1);
    playback.speed(2);
    playback.play();
    await vi.advanceTimersByTimeAsync(110);
    expect(received).toEqual([[0xff, 65], [66]]);
    expect(states.at(-1)).toBe('ended');
    await playback.restart();
    expect(states.at(-1)).toBe('paused');
    expect(reset).toHaveBeenCalledTimes(2);
    playback.play();
    await vi.advanceTimersByTimeAsync(160);
    expect(states.at(-1)).toBe('ended');
    playback.dispose();
  });

  it('joins an in-flight render before reset and suppresses stale/disposed jobs', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    let drained: (() => void) | undefined;
    const reset = vi.fn();
    const write = vi.fn((_data: Uint8Array, done: () => void) => {
      drained = done;
    });
    const states: string[] = [];
    const playback = new RecordingPlayback(image(), { reset, resize() {}, write }, (state) =>
      states.push(state.phase),
    );
    playback.play();
    await vi.advanceTimersByTimeAsync(1);
    const resetting = playback.restart();
    expect(states.at(-1)).toBe('resetting');
    expect(reset).toHaveBeenCalledOnce();
    drained?.();
    await resetting;
    expect(reset).toHaveBeenCalledTimes(2);
    expect(states.at(-1)).toBe('paused');
    playback.play();
    await vi.advanceTimersByTimeAsync(1);
    playback.dispose();
    const count = states.length;
    drained?.();
    await vi.advanceTimersByTimeAsync(1000);
    expect(states).toHaveLength(count);
    expect(write).toHaveBeenCalledTimes(2);
  });

  it('fails a non-draining renderer without successful completion or unsafe reset', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const states: string[] = [];
    const playback = new RecordingPlayback(
      image(),
      { reset() {}, resize() {}, write() {} },
      (state) => states.push(state.phase),
    );
    playback.play();
    await vi.advanceTimersByTimeAsync(5001);
    expect(states.at(-1)).toBe('failed');
    expect(states).not.toContain('ended');
    await playback.restart();
    expect(states.at(-1)).toBe('failed');
    playback.dispose();
  });
  it('applies recorded resizes locally and never clamps oversized terminal images', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const dimensions = new Uint8Array(8);
    const view = new DataView(dimensions.buffer);
    view.setUint32(0, 132, true);
    view.setUint32(4, 43, true);
    const resize = vi.fn();
    const plan = new PlaybackImage(
      options,
      { ...metadata, frames: 1, durationUs: 0 },
      wire([{ atUs: 0, kind: 3, data: dimensions }]),
    );
    const playback = new RecordingPlayback(
      plan,
      {
        reset() {},
        write(_data, done) {
          done();
        },
        resize,
      },
      () => undefined,
    );
    playback.play();
    await vi.advanceTimersByTimeAsync(1);
    expect(resize).toHaveBeenCalledWith(132, 43);
    playback.dispose();
    view.setUint32(0, 512, true);
    view.setUint32(4, 256, true);
    expect(
      () =>
        new PlaybackImage(
          options,
          { ...metadata, frames: 1 },
          wire([{ atUs: 0, kind: 3, data: dimensions }]),
        ),
    ).toThrow();
  });
});

class PlaybackWorker extends EventTarget {
  static instances: PlaybackWorker[] = [];
  static hold = false;
  terminated = false;
  requests: unknown[] = [];
  constructor(url: string, config: WorkerOptions) {
    super();
    expect(url).toBe('/_bifroest/files/browser-evidence-worker.js');
    expect(config.credentials).toBe('omit');
    PlaybackWorker.instances.push(this);
    queueMicrotask(() =>
      this.dispatchEvent(new MessageEvent('message', { data: { kind: 'ready' } })),
    );
  }
  postMessage(request: unknown) {
    this.requests.push(request);
    if (!PlaybackWorker.hold) {
      queueMicrotask(() =>
        this.dispatchEvent(
          new MessageEvent('message', {
            data: {
              kind: 'prepared',
              metadata,
              output: wire([
                { atUs: 0, kind: 0, data: new Uint8Array([1]) },
                { atUs: 200_000, kind: 0, data: new Uint8Array([2]) },
              ]),
            },
          }),
        ),
      );
    }
  }
  terminate() {
    this.terminated = true;
  }
}

describe('bearer-free one-shot playback preparation RPC', () => {
  afterEach(() => {
    PlaybackWorker.instances = [];
    PlaybackWorker.hold = false;
  });
  it('sends only local data/options and retires the worker before exposing an owned image', async () => {
    vi.stubGlobal('Worker', PlaybackWorker);
    const plan = await prepareRecordingPlayback(
      new Blob(['local signed fixture']),
      options,
      new AbortController().signal,
    );
    const worker = required(PlaybackWorker.instances[0]);
    expect(worker.terminated).toBe(true);
    expect(worker.requests).toHaveLength(1);
    expect(Object.keys(required(worker.requests[0]) as object).sort()).toEqual([
      'data',
      'kind',
      'options',
    ]);
    expect(plan.metadata.trust).toBe('pinned');
    plan.dispose();
  });
  it('aborts an owned preparation with no partial plan or surviving worker', async () => {
    vi.stubGlobal('Worker', PlaybackWorker);
    PlaybackWorker.hold = true;
    const controller = new AbortController();
    const pending = prepareRecordingPlayback(
      new Blob(['local signed fixture']),
      options,
      controller.signal,
    );
    const observed = expect(pending).rejects.toMatchObject({ code: 'cancelled' });
    await vi.waitFor(() => expect(PlaybackWorker.instances[0]?.requests.length).toBe(1));
    controller.abort();
    await observed;
    expect(required(PlaybackWorker.instances[0]).terminated).toBe(true);
  });
});
