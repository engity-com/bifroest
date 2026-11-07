import { afterEach, describe, expect, it, vi } from 'vitest';
import { type PlaybackState, RecordingPlayback } from '../src/artifacts/playback';
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

function historyImage() {
  const dimensions = new Uint8Array(8);
  const view = new DataView(dimensions.buffer);
  view.setUint32(0, 132, true);
  view.setUint32(4, 43, true);
  return new PlaybackImage(
    options,
    { ...metadata, frames: 5 },
    wire([
      { atUs: 0, kind: 0, data: new Uint8Array([0xff, 27, 91]) },
      { atUs: 50_000, kind: 0, data: new Uint8Array([50, 74]) },
      { atUs: 100_000, kind: 3, data: dimensions },
      { atUs: 100_000, kind: 0, data: new Uint8Array([65]) },
      { atUs: 300_000, kind: 0, data: new Uint8Array([66]) },
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

describe('local terminal seek reconstruction', () => {
  it('reconstructs all output and recorded resizes backwards/forwards, including exact boundaries', async () => {
    const events: unknown[] = [];
    const buffers: Uint8Array[] = [];
    let state: PlaybackState | undefined;
    const playback = new RecordingPlayback(
      historyImage(),
      {
        reset: (columns, rows) => events.push(['reset', columns, rows]),
        resize: (columns, rows) => events.push(['resize', columns, rows]),
        write(data, done) {
          buffers.push(data);
          events.push([...data]);
          done();
        },
      },
      (next) => {
        state = next;
      },
    );
    await playback.seek(100_000);
    expect(events).toEqual([
      ['reset', 80, 24],
      ['reset', 80, 24],
      [0xff, 27, 91, 50, 74],
      ['resize', 132, 43],
      [65],
    ]);
    expect(state).toMatchObject({ phase: 'paused', positionUs: 100_000 });
    events.length = 0;
    await playback.seek(-1);
    expect(events).toEqual([
      ['reset', 80, 24],
      [0xff, 27, 91],
    ]);
    expect(state).toMatchObject({ phase: 'paused', positionUs: 0 });
    events.length = 0;
    await playback.seek(1_000_000);
    expect(events).toEqual([
      ['reset', 80, 24],
      [0xff, 27, 91, 50, 74],
      ['resize', 132, 43],
      [65, 66],
    ]);
    expect(state).toMatchObject({ phase: 'paused', positionUs: 300_000 });
    expect(buffers.every((buffer) => buffer.every((byte) => byte === 0))).toBe(true);
    events.length = 0;
    await playback.restart();
    expect(events).toEqual([['reset', 80, 24]]);
    expect(state).toMatchObject({ phase: 'paused', positionUs: 0 });
    playback.dispose();
  });

  it('preserves the playing/paused intent across rapid seeks and accepts explicit play/pause overrides', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    let state: PlaybackState | undefined;
    let drained: (() => void) | undefined;
    let hold = false;
    const reset = vi.fn();
    const playback = new RecordingPlayback(
      image(),
      {
        reset,
        resize() {},
        write(_data, done) {
          if (hold) {
            drained = done;
          } else {
            done();
          }
        },
      },
      (next) => {
        state = next;
      },
    );
    playback.play();
    await vi.advanceTimersByTimeAsync(10);
    hold = true;
    const first = playback.seek(200_000);
    await vi.advanceTimersByTimeAsync(0);
    expect(state?.phase).toBe('seeking');
    const second = playback.seek(50_000);
    hold = false;
    drained?.();
    await Promise.all([first, second]);
    expect(state).toMatchObject({ phase: 'playing', positionUs: 50_000 });
    expect(reset).toHaveBeenCalledTimes(3);
    hold = true;
    const paused = playback.seek(200_000);
    await vi.advanceTimersByTimeAsync(0);
    playback.pause();
    const stillPaused = playback.seek(100_000);
    hold = false;
    drained?.();
    await Promise.all([paused, stillPaused]);
    expect(state).toMatchObject({ phase: 'paused', positionUs: 100_000 });
    const playing = playback.seek(0);
    playback.play();
    await playing;
    expect(state?.phase).toBe('playing');
    await playback.seek(100_000, false);
    expect(state?.phase).toBe('paused');
    await playback.seek(300_000, true);
    expect(state).toMatchObject({ phase: 'ended', positionUs: 300_000 });
    playback.dispose();
  });

  it('ignores nonfinite positions without changing state or pending resume intent', async () => {
    const reset = vi.fn();
    const states: PlaybackState[] = [];
    const playback = new RecordingPlayback(
      image(),
      {
        reset,
        resize() {},
        write(_data, done) {
          done();
        },
      },
      (state) => states.push(state),
    );
    for (const position of [NaN, Infinity, -Infinity]) {
      await playback.seek(position, true);
    }
    expect(states).toHaveLength(1);
    expect(reset).toHaveBeenCalledOnce();
    const pending = playback.seek(100_000);
    await playback.seek(NaN, true);
    await pending;
    expect(states.at(-1)).toMatchObject({ phase: 'paused', positionUs: 100_000 });
    playback.dispose();
  });

  it('also drains a latest request queued between completion publication and task cleanup', async () => {
    let state: PlaybackState | undefined;
    let queued: Promise<void> | undefined;
    let enqueue = true;
    const playback = new RecordingPlayback(
      image(),
      {
        reset() {},
        resize() {},
        write(_data, done) {
          done();
        },
      },
      (next) => {
        state = next;
        if (enqueue && next.phase === 'paused' && next.positionUs === 100_000) {
          enqueue = false;
          queueMicrotask(() => {
            queued = playback.seek(0);
          });
        }
      },
    );
    await playback.seek(100_000);
    await queued;
    expect(state).toMatchObject({ phase: 'paused', positionUs: 0 });
    playback.dispose();
  });

  it('handles empty/zero-duration images and never omits frames at time zero', async () => {
    for (const frames of [[], [{ atUs: 0, kind: 0, data: new Uint8Array([65]) }]]) {
      let state: PlaybackState | undefined;
      const received: number[][] = [];
      const playback = new RecordingPlayback(
        new PlaybackImage(
          options,
          { ...metadata, frames: frames.length, durationUs: 0 },
          wire(frames),
        ),
        {
          reset() {},
          resize() {},
          write(data, done) {
            received.push([...data]);
            done();
          },
        },
        (next) => {
          state = next;
        },
      );
      await playback.seek(0);
      expect(state).toMatchObject({ phase: 'paused', positionUs: 0 });
      expect(received).toEqual(frames.length === 0 ? [] : [[65]]);
      await playback.seek(0, true);
      expect(state?.phase).toBe('ended');
      playback.dispose();
    }
  });

  it('joins old playback writes before reset, coalesces requests and holds copies until callbacks', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const writes: { data: Uint8Array; done: () => void }[] = [];
    const reset = vi.fn();
    const states: PlaybackState[] = [];
    const playback = new RecordingPlayback(
      historyImage(),
      {
        reset,
        resize() {},
        write(data, done) {
          writes.push({ data, done });
        },
      },
      (state) => states.push(state),
    );
    playback.play();
    await vi.advanceTimersByTimeAsync(1);
    const first = playback.seek(300_000);
    const second = playback.seek(200_000);
    const latest = playback.seek(0, false);
    expect(reset).toHaveBeenCalledOnce();
    expect([...required(writes[0]).data]).toEqual([0xff, 27, 91]);
    required(writes[0]).done();
    await vi.advanceTimersByTimeAsync(0);
    expect(reset).toHaveBeenCalledTimes(2);
    expect(writes).toHaveLength(2);
    expect([...required(writes[0]).data]).toEqual([0, 0, 0]);
    required(writes[1]).done();
    await Promise.all([first, second, latest]);
    expect(states.at(-1)).toMatchObject({ phase: 'paused', positionUs: 0 });
    expect([...required(writes[1]).data]).toEqual([0, 0, 0]);
    playback.dispose();
  });

  it('supersedes seek/restart jobs without concurrent writes or resetting an in-flight reconstruction', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const writes: { data: Uint8Array; done: () => void }[] = [];
    const reset = vi.fn();
    let state: PlaybackState | undefined;
    const playback = new RecordingPlayback(
      historyImage(),
      {
        reset,
        resize() {},
        write(data, done) {
          writes.push({ data, done });
        },
      },
      (next) => {
        state = next;
      },
    );
    const old = playback.seek(300_000, true);
    await vi.advanceTimersByTimeAsync(0);
    const restart = playback.restart();
    expect(state?.phase).toBe('resetting');
    const latest = playback.seek(0);
    expect(reset).toHaveBeenCalledTimes(2);
    required(writes[0]).done();
    await vi.advanceTimersByTimeAsync(0);
    expect(reset).toHaveBeenCalledTimes(3);
    expect(writes).toHaveLength(2);
    required(writes[1]).done();
    await Promise.all([old, restart, latest]);
    expect(state).toMatchObject({ phase: 'paused', positionUs: 0 });
    playback.dispose();
  });

  it('stops owned seeks on dispose and ignores late callbacks without reading a disposed image', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const plan = historyImage();
    const reset = vi.fn();
    const states: PlaybackState[] = [];
    let buffer: Uint8Array | undefined;
    let drained: (() => void) | undefined;
    const playback = new RecordingPlayback(
      plan,
      {
        reset,
        resize() {},
        write(data, done) {
          buffer = data;
          drained = done;
        },
      },
      (state) => states.push(state),
    );
    const pending = playback.seek(300_000, true);
    await vi.advanceTimersByTimeAsync(0);
    playback.dispose();
    const count = states.length;
    await pending;
    expect(() => plan.frame(0)).toThrow();
    expect(buffer?.every((byte) => byte === 0)).toBe(true);
    drained?.();
    await vi.advanceTimersByTimeAsync(6000);
    await playback.seek(0);
    expect(states).toHaveLength(count);
    expect(reset).toHaveBeenCalledTimes(2);
  });

  it('keeps the 5s drain failure fatal even after seek supersession, without unsafe resets', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const reset = vi.fn();
    const states: PlaybackState[] = [];
    let data: Uint8Array | undefined;
    let done: (() => void) | undefined;
    const plan = image();
    const playback = new RecordingPlayback(
      plan,
      {
        reset,
        resize() {},
        write(bytes, callback) {
          data = bytes;
          done = callback;
        },
      },
      (state) => states.push(state),
    );
    const first = playback.seek(300_000, true);
    await vi.advanceTimersByTimeAsync(0);
    const latest = playback.seek(0);
    await vi.advanceTimersByTimeAsync(4999);
    expect(states.at(-1)?.phase).toBe('seeking');
    await vi.advanceTimersByTimeAsync(1);
    await Promise.all([first, latest]);
    expect(states.at(-1)?.phase).toBe('failed');
    expect(states.map((state) => state.phase)).not.toContain('ended');
    expect(reset).toHaveBeenCalledTimes(2);
    expect(data?.every((byte) => byte === 0)).toBe(true);
    expect(() => plan.frame(0)).toThrow();
    done?.();
    await playback.restart();
    expect(states.at(-1)?.phase).toBe('failed');
    playback.dispose();
  });

  it('does not reset when a joined playback write fails its unchanged 5s drain deadline', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const reset = vi.fn();
    const states: PlaybackState[] = [];
    const playback = new RecordingPlayback(
      image(),
      {
        reset,
        resize() {},
        write() {},
      },
      (state) => states.push(state),
    );
    playback.play();
    await vi.advanceTimersByTimeAsync(1);
    const pending = playback.seek(0);
    await vi.advanceTimersByTimeAsync(4999);
    await pending;
    expect(states.at(-1)?.phase).toBe('failed');
    expect(reset).toHaveBeenCalledOnce();
    expect(states.map((state) => state.phase)).not.toContain('ended');
    playback.dispose();
  });

  it.each(['reset', 'resize', 'write', 'write-after-done'] as const)(
    'reports %s exceptions as fatal without claiming seek success',
    async (failure) => {
      let armed = false;
      const states: PlaybackState[] = [];
      const buffers: Uint8Array[] = [];
      const plan = historyImage();
      const frameCopies: Uint8Array[] = [];
      const originalFrame = plan.frame.bind(plan);
      vi.spyOn(plan, 'frame').mockImplementation((index) => {
        const frame = originalFrame(index);
        if (frame.kind !== 3) {
          frameCopies.push(frame.data);
        }
        return frame;
      });
      const playback = new RecordingPlayback(
        plan,
        {
          reset() {
            if (armed && failure === 'reset') {
              throw new Error('reset');
            }
          },
          resize() {
            if (failure === 'resize') {
              throw new Error('resize');
            }
          },
          write(data, done) {
            buffers.push(data);
            if (failure === 'write') {
              throw new Error('write');
            }
            done();
            if (failure === 'write-after-done') {
              throw new Error('write after done');
            }
          },
        },
        (state) => states.push(state),
      );
      armed = true;
      await playback.seek(300_000, true);
      expect(states.at(-1)?.phase).toBe('failed');
      expect(states.map((state) => state.phase)).not.toContain('ended');
      expect(buffers.every((buffer) => buffer.every((byte) => byte === 0))).toBe(true);
      expect(frameCopies.every((buffer) => buffer.every((byte) => byte === 0))).toBe(true);
      expect(() => plan.frame(0)).toThrow();
      playback.dispose();
    },
  );

  it('settles disposal during a cooperative yield without another renderer write', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const frames = Array.from({ length: 2048 }, () => ({
      atUs: 0,
      kind: 0,
      data: new Uint8Array([65]),
    }));
    const write = vi.fn((_data: Uint8Array, done: () => void) => {
      done();
    });
    const playback = new RecordingPlayback(
      new PlaybackImage(options, { ...metadata, frames: frames.length }, wire(frames)),
      {
        reset() {},
        resize() {},
        write,
      },
      () => undefined,
    );
    const pending = playback.seek(0);
    // Reach the first yielded task without advancing it or the drain deadline.
    for (let index = 0; index < 10; index++) {
      await Promise.resolve();
    }
    expect(write).toHaveBeenCalledOnce();
    playback.dispose();
    await pending;
    expect(write).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('bounds merged output to 64KiB and wipes both submitted and overflow lookahead copies', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const frames = [40_000, 40_000, 20_000, 6000, 65_536].map((size, index) => ({
      atUs: 0,
      kind: 0,
      data: new Uint8Array(size).fill(index + 1),
    }));
    const plan = new PlaybackImage(options, { ...metadata, frames: frames.length }, wire(frames));
    const frameCopies: Uint8Array[] = [];
    const originalFrame = plan.frame.bind(plan);
    vi.spyOn(plan, 'frame').mockImplementation((index) => {
      const frame = originalFrame(index);
      if (frame.kind !== 3) {
        frameCopies.push(frame.data);
      }
      return frame;
    });
    const lengths: number[] = [];
    const buffers: Uint8Array[] = [];
    const output: number[] = [];
    const playback = new RecordingPlayback(
      plan,
      {
        reset() {},
        resize() {},
        write(data, done) {
          lengths.push(data.length);
          buffers.push(data);
          output.push(...data);
          done();
        },
      },
      () => undefined,
    );
    const pending = playback.seek(0);
    await vi.runAllTimersAsync();
    await pending;
    expect(lengths).toEqual([40_000, 60_000, 6000, 65_536]);
    expect(output).toEqual(frames.flatMap((frame) => [...frame.data]));
    expect(buffers.every((buffer) => buffer.every((byte) => byte === 0))).toBe(true);
    expect(frameCopies.every((buffer) => buffer.every((byte) => byte === 0))).toBe(true);
    playback.dispose();
  });

  it('continues from the first frame after the inclusive seek target using the selected local speed', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const output: number[][] = [];
    let state: PlaybackState | undefined;
    const playback = new RecordingPlayback(
      image(),
      {
        reset() {},
        resize() {},
        write(data, done) {
          output.push([...data]);
          done();
        },
      },
      (next) => {
        state = next;
      },
    );
    await playback.seek(100_000);
    playback.speed(2);
    playback.play();
    await vi.advanceTimersByTimeAsync(49);
    expect(output).toEqual([[0xff, 65]]);
    await vi.advanceTimersByTimeAsync(1);
    expect(output).toEqual([[0xff, 65], [66]]);
    await vi.advanceTimersByTimeAsync(50);
    expect(state).toMatchObject({ phase: 'ended', positionUs: 300_000, speed: 2 });
    playback.dispose();
  });

  it('batches 100k events in order with <=64KiB writes and yields to newer intent', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const count = 100_000;
    const frames = Array.from({ length: count }, (_, index) => ({
      atUs: index,
      kind: 0,
      data: new Uint8Array([index % 251]),
    }));
    const writes: Uint8Array[] = [];
    const output: number[] = [];
    const reset = vi.fn();
    let state: PlaybackState | undefined;
    const playback = new RecordingPlayback(
      new PlaybackImage(options, { ...metadata, frames: count }, wire(frames)),
      {
        reset,
        resize() {},
        write(data, done) {
          expect(data.length).toBeLessThanOrEqual(64 << 10);
          writes.push(data);
          output.push(...data);
          done();
        },
      },
      (next) => {
        state = next;
      },
    );
    let interrupted: Promise<void> | undefined;
    setTimeout(() => {
      interrupted = playback.seek(0);
    }, 0);
    const first = playback.seek(100_000);
    await vi.runAllTimersAsync();
    await first;
    await interrupted;
    expect(state).toMatchObject({ phase: 'paused', positionUs: 0 });
    expect(output.length).toBeLessThan(count);
    output.length = 0;
    const complete = playback.seek(300_000);
    await vi.runAllTimersAsync();
    await complete;
    expect(output).toEqual(frames.map((frame) => frame.data[0]));
    expect(writes.length).toBeLessThan(1000);
    expect(writes.every((buffer) => buffer.every((byte) => byte === 0))).toBe(true);
    playback.dispose();
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
