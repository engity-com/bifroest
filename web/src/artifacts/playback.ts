import type { PlaybackImage } from './playback-protocol';

export type PlaybackPhase =
    | 'paused'
    | 'playing'
    | 'seeking'
    | 'resetting'
    | 'ended'
    | 'failed'
    | 'stopped';
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

interface Reconstruction {
    readonly positionUs: number;
    readonly phase: 'seeking' | 'resetting';
    resume: boolean;
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
    #reconstruction: Reconstruction | null = null;
    #reconstructionTask: Promise<void> | null = null;
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
                (this.#phase === 'playing'
                    ? (performance.now() - this.#epoch) * 1000 * this.#speed
                    : 0),
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
                    this.#schedule(
                        (this.#image.metadata.durationUs - position) / 1000 / this.#speed,
                    );
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
            let writing = true;
            let drained = false;
            try {
                this.#renderer.write(data, () => {
                    // A synchronous callback cannot hide an exception thrown before the
                    // renderer's write call returns.
                    if (writing) {
                        drained = true;
                    } else {
                        finish();
                    }
                });
                writing = false;
                if (drained) {
                    finish();
                }
            } catch {
                finish(new Error('local playback rendering failed'));
            } finally {
                writing = false;
            }
        });
    }
    #fail() {
        this.#position = this.#clock();
        this.#phase = 'failed';
        this.#reconstruction = null;
        this.#generation++;
        this.#clearTimer();
        this.#image.dispose();
        this.#publish();
    }
    play() {
        if (this.#phase === 'seeking' && this.#reconstruction !== null) {
            this.#reconstruction.resume = true;
            return;
        }
        if (this.#phase !== 'paused') {
            return;
        }
        this.#epoch = performance.now();
        this.#phase = 'playing';
        this.#publish();
        this.#kick();
    }
    pause() {
        if (this.#phase === 'seeking' && this.#reconstruction !== null) {
            this.#reconstruction.resume = false;
            return;
        }
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
    /** Reconstruct local terminal history through the inclusive, clamped target.
     * Nonfinite positions are ignored. Superseded callers join the latest target;
     * renderer failure is reported as a terminal `failed` state, as with restart.
     */
    seek(positionUs: number, resume?: boolean): Promise<void> {
        if (!Number.isFinite(positionUs) || this.#phase === 'stopped' || this.#phase === 'failed') {
            return Promise.resolve();
        }
        return this.#requestReconstruction({
            positionUs: Math.max(0, Math.min(this.#image.metadata.durationUs, positionUs)),
            phase: 'seeking',
            resume: resume ?? this.#reconstruction?.resume ?? this.#phase === 'playing',
        });
    }
    restart(): Promise<void> {
        if (this.#phase === 'stopped' || this.#phase === 'failed' || this.#phase === 'resetting') {
            return Promise.resolve();
        }
        return this.#requestReconstruction({ positionUs: 0, phase: 'resetting', resume: false });
    }
    #requestReconstruction(request: Reconstruction): Promise<void> {
        this.#generation++;
        this.#reconstruction = request;
        this.#position = request.positionUs;
        this.#phase = request.phase;
        this.#clearTimer();
        this.#publish();
        return this.#reconstructionTask ?? this.#startReconstruction();
    }
    #startReconstruction(): Promise<void> {
        // Assign before any renderer work: reentrant or rapid requests share one
        // flight, and no reset can overlap an older write (including playback).
        this.#reconstructionTask = Promise.resolve()
            .then(() => this.#rebuild())
            .finally(() => {
                this.#reconstructionTask = null;
                // A state subscriber can enqueue a seek in the microtask between the
                // rebuild's return and this cleanup. Join it rather than stranding it.
                if (this.#reconstruction !== null && !this.#stop.signal.aborted) {
                    return this.#startReconstruction();
                }
            });
        return this.#reconstructionTask;
    }
    #current(request: Reconstruction): boolean {
        return !this.#stop.signal.aborted && this.#reconstruction === request;
    }
    async #rebuild() {
        try {
            // Rejected writes are still joined. Their renderer-failure flag must not
            // be hidden by a generation change when seeking supersedes playback.
            await this.#task?.catch(() => undefined);
            if (this.#stop.signal.aborted) {
                return;
            }
            if (this.#rendererFailed) {
                this.#fail();
                return;
            }
            while (this.#reconstruction !== null && !this.#stop.signal.aborted) {
                const request = this.#reconstruction;
                this.#renderer.reset(this.#image.metadata.columns, this.#image.metadata.rows);
                const index = request.phase === 'resetting' ? 0 : await this.#reconstruct(request);
                if (!this.#current(request)) {
                    continue;
                }
                this.#index = index;
                this.#position = request.positionUs;
                this.#epoch = performance.now();
                this.#reconstruction = null;
                this.#phase = request.resume
                    ? request.positionUs === this.#image.metadata.durationUs
                        ? 'ended'
                        : 'playing'
                    : 'paused';
                this.#publish();
                this.#kick();
            }
        } catch {
            if (!this.#stop.signal.aborted) {
                this.#rendererFailed = true;
                this.#fail();
            }
        }
    }
    async #reconstruct(request: Reconstruction): Promise<number> {
        let index = 0;
        let work = 0;
        let bytes = 0;
        const eligible = () =>
            index < this.#image.metadata.frames && this.#image.time(index) <= request.positionUs;
        while (this.#current(request) && eligible()) {
            const frame = this.#image.frame(index);
            if (frame.kind === 3) {
                this.#renderer.resize(frame.columns, frame.rows);
                index++;
                work++;
            } else {
                // Adjacent output can share a bounded write, never crossing a resize.
                // Keep every submitted copy alive until drain, then wipe on all paths.
                const copies = [frame.data];
                let size = frame.data.length;
                let data = frame.data;
                index++;
                work++;
                try {
                    while (work < 1024 && size < 64 << 10 && eligible()) {
                        const next = this.#image.frame(index);
                        if (next.kind === 3) {
                            break;
                        }
                        if (size + next.data.length > 64 << 10) {
                            next.data.fill(0);
                            break;
                        }
                        copies.push(next.data);
                        size += next.data.length;
                        index++;
                        work++;
                    }
                    if (copies.length > 1) {
                        data = new Uint8Array(size);
                        let offset = 0;
                        for (const copy of copies) {
                            data.set(copy, offset);
                            offset += copy.length;
                        }
                    }
                    await this.#write(data);
                    bytes += size;
                } finally {
                    data.fill(0);
                    for (const copy of copies) {
                        copy.fill(0);
                    }
                }
            }
            if ((work >= 1024 || bytes >= 64 << 10) && this.#current(request) && eligible()) {
                // Yield a task, not only a microtask: sliders/disposal must interrupt a
                // 100k-event reconstruction even with synchronous renderer callbacks.
                await new Promise<void>((resolve) => {
                    const finish = () => {
                        clearTimeout(timer);
                        this.#stop.signal.removeEventListener('abort', finish);
                        resolve();
                    };
                    const timer = setTimeout(finish, 0);
                    this.#stop.signal.addEventListener('abort', finish, { once: true });
                });
                work = 0;
                bytes = 0;
            }
        }
        return index;
    }
    dispose() {
        if (this.#phase === 'stopped') {
            return;
        }
        this.#position = this.#clock();
        this.#phase = 'stopped';
        this.#reconstruction = null;
        this.#generation++;
        this.#clearTimer();
        this.#stop.abort();
        this.#image.dispose();
    }
}
