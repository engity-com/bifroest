import { object } from '../remember/http';
import { EvidenceError } from './evidence-protocol';
import { maximumBufferedArtifactBytes } from './protocol';

export const maximumPlaybackEvents = 100_000;
export const maximumPlaybackDurationUs = 10 * 365 * 24 * 60 * 60 * 1_000_000;

export interface PlaybackOptions {
  readonly id: string;
  readonly producer: string;
  readonly allowUntrusted: boolean;
}
export interface PlaybackMetadata {
  readonly version: 1;
  readonly recordingId: string;
  readonly producer: string;
  readonly trust: 'pinned' | 'untrusted';
  readonly columns: number;
  readonly rows: number;
  readonly pty: boolean;
  readonly frames: number;
  readonly durationUs: number;
  readonly status: 'completed' | 'failed' | 'incomplete';
  readonly exitStatus: number | null;
}

export function playbackOptions(value: unknown): PlaybackOptions {
  try {
    const body = object(value, ['id', 'producer', 'allowUntrusted']);
    if (
      typeof body.id !== 'string' ||
      !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(body.id) ||
      body.id === '00000000-0000-0000-0000-000000000000' ||
      typeof body.producer !== 'string' ||
      (body.producer !== '' &&
        (!/^[0-9a-f]{64}$/u.test(body.producer) || /^0+$/u.test(body.producer))) ||
      typeof body.allowUntrusted !== 'boolean' ||
      (body.producer === '' && !body.allowUntrusted)
    ) {
      throw new Error();
    }
    return Object.freeze({
      id: body.id,
      producer: body.producer,
      allowUntrusted: body.allowUntrusted,
    });
  } catch {
    throw new EvidenceError('input');
  }
}

export function playbackDimensions(columns: number, rows: number): boolean {
  return (
    Number.isInteger(columns) &&
    columns > 0 &&
    columns <= 512 &&
    Number.isInteger(rows) &&
    rows > 0 &&
    rows <= 256 &&
    columns * rows <= 32_768
  );
}

export function playbackMetadata(options: PlaybackOptions, value: unknown): PlaybackMetadata {
  try {
    const body = object(value, [
      'version',
      'recordingId',
      'producer',
      'trust',
      'columns',
      'rows',
      'pty',
      'frames',
      'durationUs',
      'status',
      'exitStatus',
    ]);
    if (
      body.version !== 1 ||
      body.recordingId !== options.id ||
      typeof body.producer !== 'string' ||
      !/^[0-9a-f]{64}$/u.test(body.producer) ||
      /^0+$/u.test(body.producer) ||
      (options.producer !== '' &&
        (body.producer !== options.producer || body.trust !== 'pinned')) ||
      (options.producer === '' && body.trust !== 'untrusted') ||
      typeof body.columns !== 'number' ||
      typeof body.rows !== 'number' ||
      !playbackDimensions(body.columns, body.rows) ||
      typeof body.pty !== 'boolean' ||
      !Number.isInteger(body.frames) ||
      (body.frames as number) < 0 ||
      (body.frames as number) > maximumPlaybackEvents ||
      !Number.isSafeInteger(body.durationUs) ||
      (body.durationUs as number) < 0 ||
      (body.durationUs as number) > maximumPlaybackDurationUs ||
      typeof body.status !== 'string' ||
      !['completed', 'failed', 'incomplete'].includes(body.status) ||
      (body.exitStatus !== null &&
        (!Number.isInteger(body.exitStatus) ||
          (body.exitStatus as number) < 0 ||
          (body.exitStatus as number) > 0x7fffffff)) ||
      (body.status === 'completed' && body.exitStatus === null)
    ) {
      throw new Error();
    }
    return Object.freeze({ ...body }) as unknown as PlaybackMetadata;
  } catch {
    throw new EvidenceError('verification');
  }
}

export type PlaybackFrame =
  | { readonly atUs: number; readonly kind: 0 | 1 | 2; readonly data: Uint8Array<ArrayBuffer> }
  | { readonly atUs: number; readonly kind: 3; readonly columns: number; readonly rows: number };

// Owned local rendering transport. Callers never receive a mutable view of the
// image; each output frame is copied before entering an asynchronous renderer.
export class PlaybackImage {
  readonly metadata: PlaybackMetadata;
  readonly #bytes: Uint8Array<ArrayBuffer>;
  readonly #frames: { atUs: number; kind: 0 | 1 | 2 | 3; offset: number; size: number }[] = [];
  #disposed = false;

  constructor(options: PlaybackOptions, metadata: unknown, image: ArrayBuffer) {
    try {
      options = playbackOptions(options);
      this.metadata = playbackMetadata(options, metadata);
    } catch (error) {
      new Uint8Array(image).fill(0);
      throw error;
    }
    this.#bytes = new Uint8Array(structuredClone(image, { transfer: [image] }));
    try {
      if (this.#bytes.byteLength > maximumBufferedArtifactBytes) {
        throw new Error();
      }
      const view = new DataView(this.#bytes.buffer);
      let offset = 0;
      let previous = 0;
      for (let index = 0; index < this.metadata.frames; index++) {
        if (offset + 13 > this.#bytes.byteLength) {
          throw new Error();
        }
        const atUs = Number(view.getBigUint64(offset, true));
        const kind = view.getUint8(offset + 8);
        const size = view.getUint32(offset + 9, true);
        offset += 13;
        if (
          !Number.isSafeInteger(atUs) ||
          atUs < previous ||
          atUs > this.metadata.durationUs ||
          kind > 3 ||
          offset + size > this.#bytes.byteLength ||
          (this.metadata.pty && kind !== 0 && kind !== 3) ||
          (!this.metadata.pty && (kind === 0 || kind === 3))
        ) {
          throw new Error();
        }
        if (kind === 3) {
          if (
            size !== 8 ||
            !playbackDimensions(view.getUint32(offset, true), view.getUint32(offset + 4, true))
          ) {
            throw new Error();
          }
        } else if (size > 64 << 10) {
          throw new Error();
        }
        this.#frames.push({ atUs, kind: kind as 0 | 1 | 2 | 3, offset, size });
        previous = atUs;
        offset += size;
      }
      if (offset !== this.#bytes.byteLength) {
        throw new Error();
      }
    } catch {
      this.dispose();
      throw new EvidenceError('verification');
    }
  }

  time(index: number): number {
    const frame = this.#frames[index];
    if (this.#disposed || !Number.isInteger(index) || frame === undefined) {
      throw new EvidenceError('unavailable');
    }
    return frame.atUs;
  }

  frame(index: number): PlaybackFrame {
    const frame = this.#frames[index];
    if (this.#disposed || !Number.isInteger(index) || frame === undefined) {
      throw new EvidenceError('unavailable');
    }
    if (frame.kind === 3) {
      const view = new DataView(this.#bytes.buffer);
      return {
        atUs: frame.atUs,
        kind: 3,
        columns: view.getUint32(frame.offset, true),
        rows: view.getUint32(frame.offset + 4, true),
      };
    }
    return {
      atUs: frame.atUs,
      kind: frame.kind,
      data: this.#bytes.slice(frame.offset, frame.offset + frame.size),
    };
  }

  dispose() {
    this.#disposed = true;
    this.#bytes.fill(0);
    this.#frames.length = 0;
  }
}
