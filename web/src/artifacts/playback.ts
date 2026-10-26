import type { PlaybackImage } from './playback-protocol';

export type PlaybackPhase = 'paused' | 'playing' | 'resetting' | 'ended' | 'failed' | 'stopped';
export interface PlaybackState {
  readonly phase: PlaybackPhase;
  readonly positionUs: number;
  readonly speed: number;
}
export interface PlaybackRenderer {
  write(data: Uint8Array<ArrayBuffer>, done: () => void): void;
  resize(columns: number, rows: number): void;
  reset(columns: number, rows: number): void;
}

// No network, input/EOF/signal channel or execution permission: this schedules
// only fully prepared local events, with at most one bounded renderer write.
export class RecordingPlayback {
  readonly #image: PlaybackImage;
  readonly #renderer: PlaybackRenderer;
  readonly #onState: (state: PlaybackState) => void;
  readonly #stop = new AbortController();
  #phase: PlaybackPhase = 'paused';
  #speed = 1;
  #position = 0;
  #epoch = 0;
  #index = 0;
  #generation = 0;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #task: Promise<void> | null = null;
  #rendererFailed = false;

  constructor(
    image: PlaybackImage,
    renderer: PlaybackRenderer,
    onState: (state: PlaybackState) => void,
  ) {
    this.#image = image;
    this.#renderer = renderer;
    this.#onState = onState;
    try {
      renderer.reset(image.metadata.columns, image.metadata.rows);
      this.#publish();
    } catch (error) {
      image.dispose();
      throw error;
    }
  }
  #clock(): number {
    return Math.min(
      this.#image.metadata.durationUs,
      this.#position +
        (this.#phase === 'playing' ? (performance.now() - this.#epoch) * 1000 * this.#speed : 0),
    );
  }
  #publish() {
    this.#onState(
      Object.freeze({ phase: this.#phase, positionUs: this.#clock(), speed: this.#speed }),
    );
  }
  #clearTimer() {
    clearTimeout(this.#timer);
    this.#timer = undefined;
  }
  #schedule(delay: number) {
    if (this.#phase !== 'playing' || this.#timer !== undefined) {
      return;
    }
    this.#timer = setTimeout(
      () => {
        this.#timer = undefined;
        this.#kick();
      },
      Math.min(100, Math.max(0, delay)),
    );
  }
  #kick() {
    if (this.#phase !== 'playing' || this.#task !== null) {
      return;
    }
    const generation = this.#generation;
    const task = Promise.resolve().then(() => this.#pump(generation));
    this.#task = task;
    void task
      .catch(() => {
        if (!this.#stop.signal.aborted && generation === this.#generation) {
          this.#fail();
        }
      })
      .finally(() => {
        if (this.#task === task) {
          this.#task = null;
          if (this.#phase === 'playing') {
            this.#schedule(0);
          }
        }
      });
  }
  async #pump(generation: number) {
    for (
      let batch = 0;
      batch < 16 && this.#phase === 'playing' && generation === this.#generation;
      batch++
    ) {
      const position = this.#clock();
      if (this.#index >= this.#image.metadata.frames) {
        if (position < this.#image.metadata.durationUs) {
          this.#publish();
          this.#schedule((this.#image.metadata.durationUs - position) / 1000 / this.#speed);
          return;
        }
        this.#position = this.#image.metadata.durationUs;
        this.#phase = 'ended';
        this.#publish();
        return;
      }
      const atUs = this.#image.time(this.#index);
      if (atUs > position) {
        this.#publish();
        this.#schedule((atUs - position) / 1000 / this.#speed);
        return;
      }
      const frame = this.#image.frame(this.#index++);
      try {
        if (frame.kind === 3) {
          this.#renderer.resize(frame.columns, frame.rows);
        } else {
          try {
            await this.#write(frame.data);
          } finally {
            frame.data.fill(0);
          }
        }
      } catch (error) {
        if (!this.#stop.signal.aborted) {
          this.#rendererFailed = true;
        }
        throw error;
      }
      if (generation === this.#generation && this.#phase === 'playing') {
        this.#publish();
      }
    }
  }
  #write(data: Uint8Array<ArrayBuffer>): Promise<void> {
    return new Promise((resolve, reject) => {
      let done = false;
      const finish = (error?: Error) => {
        if (done) {
          return;
        }
        done = true;
        clearTimeout(timer);
        this.#stop.signal.removeEventListener('abort', aborted);
        error === undefined ? resolve() : reject(error);
      };
      const aborted = () => finish(new Error('local playback stopped'));
      const timer = setTimeout(
        () => finish(new Error('local playback renderer did not drain')),
        5000,
      );
      this.#stop.signal.addEventListener('abort', aborted, { once: true });
      if (this.#stop.signal.aborted) {
        aborted();
        return;
      }
      try {
        this.#renderer.write(data, () => finish());
      } catch {
        finish(new Error('local playback rendering failed'));
      }
    });
  }
  #fail() {
    this.#phase = 'failed';
    this.#generation++;
    this.#clearTimer();
    this.#image.dispose();
    this.#publish();
  }
  play() {
    if (this.#phase !== 'paused') {
      return;
    }
    this.#epoch = performance.now();
    this.#phase = 'playing';
    this.#publish();
    this.#kick();
  }
  pause() {
    if (this.#phase !== 'playing') {
      return;
    }
    this.#position = this.#clock();
    this.#phase = 'paused';
    this.#clearTimer();
    this.#publish();
  }
  speed(value: number) {
    if (
      !Number.isFinite(value) ||
      value < 0.25 ||
      value > 8 ||
      this.#phase === 'stopped' ||
      this.#phase === 'failed' ||
      this.#phase === 'resetting'
    ) {
      return;
    }
    this.#position = this.#clock();
    this.#epoch = performance.now();
    this.#speed = value;
    this.#clearTimer();
    this.#publish();
    if (this.#phase === 'playing') {
      this.#schedule(0);
    }
  }
  async restart() {
    if (this.#phase === 'stopped' || this.#phase === 'failed' || this.#phase === 'resetting') {
      return;
    }
    this.pause();
    const generation = ++this.#generation;
    this.#phase = 'resetting';
    this.#clearTimer();
    this.#publish();
    await this.#task?.catch(() => undefined);
    if (this.#stop.signal.aborted || generation !== this.#generation) {
      return;
    }
    if (this.#rendererFailed) {
      this.#fail();
      return;
    }
    try {
      this.#renderer.reset(this.#image.metadata.columns, this.#image.metadata.rows);
    } catch {
      this.#rendererFailed = true;
      this.#fail();
      return;
    }
    this.#index = 0;
    this.#position = 0;
    this.#phase = 'paused';
    this.#publish();
  }
  dispose() {
    if (this.#phase === 'stopped') {
      return;
    }
    this.#position = this.#clock();
    this.#phase = 'stopped';
    this.#generation++;
    this.#clearTimer();
    this.#stop.abort();
    this.#image.dispose();
  }
}
