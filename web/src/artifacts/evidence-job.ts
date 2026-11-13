import { type OperationLease, OperationSlot } from '../shared/operation';
import { SnapshotObservers } from '../shared/snapshot-observers';

export type ArtifactPhase = 'downloading' | 'inspecting' | 'verifying' | 'preparing';

import type { ReadProgress } from '../management/progress';
export type EvidenceJobState =
    | { readonly phase: null; readonly progress: null }
    | { readonly phase: ArtifactPhase; readonly progress: ReadProgress | null };

// Execution ownership only. Results, keys, routes and UI messages are not kept
// here. Retiring a source makes every outstanding lease permanently stale.
export class EvidenceJob {
    constructor(private readonly allowed: () => boolean = () => true) {}
    #state: EvidenceJobState = { phase: null, progress: null };
    readonly #slot = new OperationSlot();
    readonly #observers = new SnapshotObservers();
    readonly getSnapshot = () => this.#state;
    readonly subscribe = this.#observers.subscribe;
    get busy(): boolean {
        return this.#slot.busy;
    }
    #publish(state: EvidenceJobState): void {
        this.#state = Object.freeze(state);
        this.#observers.notify();
    }
    progress(lease: OperationLease, value: ReadProgress | null): void {
        if (this.allowed() && lease.current() && this.#state.phase !== null) {
            this.#publish({ ...this.#state, progress: value });
        }
    }
    cancel(): void {
        this.#slot.cancel();
    }
    retire(): void {
        this.#publish({ phase: null, progress: null });
        this.#slot.retire();
    }
    async run(
        phase: ArtifactPhase,
        action: (lease: OperationLease, stage: (value: ArtifactPhase) => void) => Promise<void>,
        failure: (error: unknown, phase: ArtifactPhase) => void,
        cleanup: () => void,
    ): Promise<void> {
        if (!this.allowed()) {
            return;
        }
        const lease = this.#slot.start();
        if (!lease) {
            return;
        }
        let stage = phase;
        this.#publish({ phase, progress: null });
        try {
            await action(lease, (value) => {
                stage = value;
                if (lease.current()) {
                    this.#publish({ ...this.#state, phase: value });
                }
            });
        } catch (error) {
            if (lease.owned()) {
                failure(error, stage);
            }
        } finally {
            if (lease.owned()) {
                try {
                    cleanup();
                } finally {
                    if (lease.owned()) {
                        lease.finish();
                        this.#publish({ phase: null, progress: null });
                    }
                }
            }
        }
    }
}
