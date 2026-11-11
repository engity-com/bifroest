import type { ArtifactRequest } from '../artifacts/protocol';
import {
  maximumTransferImageBytes,
  recordingSourceMediaType,
  transferMediaType,
} from '../artifacts/protocol';
import { type ArtifactResponseImage, object } from '../remember/http';
import { RememberMeError } from '../remember/protocol';
import { resourceID } from '../shared/uuid';
import { type ProgressListener, remoteReadProgress } from './progress';
import { ManagementResponseBuffer } from './response-buffer';

export interface RecordingSourceImage {
  request: ArtifactRequest;
  image: ArtifactResponseImage;
  index: number;
  total: number;
  encrypted: boolean;
  recipient: string;
}
export interface RecordingSourceImages extends AsyncIterableIterator<RecordingSourceImage> {
  readonly closed: Promise<void>;
  cancel(): void;
}

// One credit authorizes at most one bounded, server-completed response image.
// Native transport decoding still has to check every selector, data-end,
// post-driver completion and physical EOF before these bytes become an artifact.
export class ManagementSourceTransfer implements RecordingSourceImages {
  readonly ready: Promise<RecordingSourceImages>;
  readonly closed: Promise<void>;
  #ready!: (value: RecordingSourceImages) => void;
  #rejectReady!: (error: RememberMeError) => void;
  #close!: () => void;
  #status: number | null = null;
  #started = false;
  #finished = false;
  #aborted = false;
  #error: RememberMeError | null = null;
  #total = -1;
  #received = 0;
  #errorBytes = 0;
  #current: {
    id: string;
    buffer: ManagementResponseBuffer;
    length: number;
    encrypted: boolean;
    recipient: string;
  } | null = null;
  #next: {
    resolve(value: IteratorResult<RecordingSourceImage>): void;
    reject(error: RememberMeError): void;
  } | null = null;
  #retired: ReturnType<typeof setTimeout> | undefined;
  #progressAt = 0;
  constructor(
    readonly id: string,
    readonly source: string,
    readonly signal: AbortSignal,
    readonly send: (message: unknown) => void,
    readonly remove: () => void,
    readonly stop: () => void,
    readonly progress?: ProgressListener,
  ) {
    this.ready = new Promise((resolve, reject) => {
      this.#ready = resolve;
      this.#rejectReady = reject;
    });
    void this.ready.catch(() => {});
    this.closed = new Promise((resolve) => {
      this.#close = resolve;
    });
    signal.addEventListener('abort', this.cancel, { once: true });
  }
  [Symbol.asyncIterator](): RecordingSourceImages {
    return this;
  }
  async next(): Promise<IteratorResult<RecordingSourceImage>> {
    await this.ready;
    if (this.#error) {
      throw this.#error;
    }
    if (this.#finished) {
      return { done: true, value: undefined };
    }
    if (this.#next) {
      throw new RememberMeError('busy');
    }
    return new Promise((resolve, reject) => {
      this.#next = { resolve, reject };
      if (this.#received < this.#total) {
        this.send({ type: 'source-next', requestId: this.id, index: String(this.#received + 1) });
      }
    });
  }
  async return(): Promise<IteratorResult<RecordingSourceImage>> {
    this.cancel();
    await this.closed;
    return { done: true, value: undefined };
  }
  cancel = (): void => {
    if (this.#finished || this.#aborted) {
      return;
    }
    this.#aborted = true;
    this.#error = new RememberMeError('cancelled');
    this.#rejectWaiters(this.#error);
    this.#current?.buffer.wipe();
    this.#current = null;
    this.send({ type: 'cancel', requestId: this.id });
    this.#retired = setTimeout(this.stop, 5000);
  };
  interrupt(error: RememberMeError): void {
    this.#finish(error);
  }
  append(data: Uint8Array): void {
    if (this.#aborted) {
      return;
    }
    if (this.#status === null) {
      throw new Error();
    }
    if (this.#status !== 200) {
      this.#errorBytes += data.byteLength;
      if (this.#errorBytes > 64 << 10) {
        throw new Error();
      }
      return;
    }
    const current = this.#current;
    if (!current || current.length + data.byteLength > maximumTransferImageBytes) {
      throw new Error();
    }
    current.length += data.byteLength;
    current.buffer.append(data);
    if (performance.now() - this.#progressAt >= 100) {
      this.#progressAt = performance.now();
      this.progress?.({ phase: 'receiving', completed: current.length, total: -1 });
    }
  }
  receive(decoded: Record<string, unknown>): void {
    if (decoded.requestId !== this.id) {
      throw new Error();
    }
    if (this.#aborted) {
      if (decoded.type === 'complete' || decoded.type === 'canceled') {
        object(decoded, ['type', 'requestId']);
        this.#finish(this.#error ?? new RememberMeError('cancelled'));
      }
      return;
    }
    switch (decoded.type) {
      case 'response': {
        const value = object(decoded, ['type', 'requestId', 'status', 'contentType']);
        if (
          this.#status !== null ||
          !Number.isInteger(value.status) ||
          Number(value.status) < 200 ||
          Number(value.status) > 599 ||
          typeof value.contentType !== 'string'
        ) {
          throw new Error();
        }
        this.#status = Number(value.status);
        if (this.#status === 200 && value.contentType !== recordingSourceMediaType) {
          throw new Error();
        }
        return;
      }
      case 'progress': {
        const value = object(decoded, ['type', 'requestId', 'phase', 'completed', 'total']);
        if (this.#status !== null) {
          throw new Error();
        }
        this.progress?.(
          remoteReadProgress({
            phase: value.phase,
            completed: value.completed,
            total: value.total,
          }),
        );
        return;
      }
      case 'source-start': {
        const value = object(decoded, ['type', 'requestId', 'source', 'total']);
        if (
          this.#status !== 200 ||
          this.#started ||
          value.source !== this.source ||
          !Number.isSafeInteger(value.total) ||
          Number(value.total) < 0
        ) {
          throw new Error();
        }
        this.#started = true;
        this.#total = Number(value.total);
        this.#ready(this);
        return;
      }
      case 'source-entry': {
        const value = object(decoded, [
          'type',
          'requestId',
          'index',
          'recordingId',
          'status',
          'contentType',
          'encrypted',
          'recipient',
        ]);
        if (
          !this.#started ||
          this.#current ||
          !this.#next ||
          value.index !== this.#received + 1 ||
          Number(value.index) > this.#total ||
          typeof value.recordingId !== 'string' ||
          !resourceID(value.recordingId) ||
          /^0{8}-(?:0{4}-){3}0{12}$/u.test(value.recordingId) ||
          value.status !== 200 ||
          value.contentType !== transferMediaType
        ) {
          throw new Error();
        }
        if (
          typeof value.encrypted !== 'boolean' ||
          typeof value.recipient !== 'string' ||
          value.encrypted !== (value.recipient !== '') ||
          (value.recipient !== '' && !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(value.recipient))
        ) {
          throw new Error();
        }
        this.#current = {
          id: value.recordingId,
          buffer: new ManagementResponseBuffer(maximumTransferImageBytes),
          length: 0,
          encrypted: value.encrypted,
          recipient: value.recipient,
        };
        return;
      }
      case 'source-entry-complete': {
        const value = object(decoded, ['type', 'requestId', 'index']);
        const current = this.#current;
        const next = this.#next;
        if (!current || !next || value.index !== this.#received + 1 || current.length === 0) {
          throw new Error();
        }
        const bytes = current.buffer.assemble();
        this.#current = null;
        this.#next = null;
        this.#received++;
        next.resolve({
          done: false,
          value: {
            request: { kind: 'recording', auditlog: this.source, id: current.id },
            image: { bytes, mediaType: transferMediaType, status: 200 },
            index: this.#received,
            total: this.#total,
            encrypted: current.encrypted,
            recipient: current.recipient,
          },
        });
        return;
      }
      case 'source-failed': {
        const value = object(decoded, ['type', 'requestId', 'status']);
        if (
          !Number.isInteger(value.status) ||
          Number(value.status) < 400 ||
          Number(value.status) > 599
        ) {
          throw new Error();
        }
        this.#error = this.#statusError(Number(value.status));
        this.#aborted = true;
        this.#rejectWaiters(this.#error);
        this.#current?.buffer.wipe();
        this.#current = null;
        this.#retired = setTimeout(this.stop, 5000);
        return;
      }
      case 'canceled':
        object(decoded, ['type', 'requestId']);
        this.#finish(new RememberMeError('unavailable'));
        return;
      case 'complete': {
        object(decoded, ['type', 'requestId']);
        if (this.#status !== 200) {
          this.#finish(this.#statusError(this.#status ?? 503));
          return;
        }
        if (!this.#started || this.#current || this.#received !== this.#total) {
          throw new Error();
        }
        this.#finish();
        return;
      }
      default:
        throw new Error();
    }
  }
  #statusError(status: number): RememberMeError {
    return new RememberMeError(
      status === 401 || status === 403 ? 'denied' : status === 429 ? 'rate-limited' : 'unavailable',
    );
  }
  #rejectWaiters(error: RememberMeError): void {
    this.#rejectReady(error);
    this.#next?.reject(error);
    this.#next = null;
  }
  #finish(error?: RememberMeError): void {
    if (this.#finished) {
      return;
    }
    this.#finished = true;
    this.#error = error ?? this.#error;
    clearTimeout(this.#retired);
    this.signal.removeEventListener('abort', this.cancel);
    this.#current?.buffer.wipe();
    this.#current = null;
    if (this.#error) {
      this.#rejectWaiters(this.#error);
    } else {
      this.#next?.resolve({ done: true, value: undefined });
      this.#next = null;
    }
    this.remove();
    this.#close();
  }
}
