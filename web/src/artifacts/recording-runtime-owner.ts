import { uuidEqual } from '../shared/uuid';
import { EvidenceError } from './evidence-protocol';
import type { ReceivedArtifact } from './protocol';
import { createRecordingRuntime, type RecordingRuntime } from './verify';

interface RuntimeSlot {
    readonly source: string;
    readonly id: string;
    readonly controller: AbortController;
    value: RecordingRuntime | undefined;
}

// One owner's compiled worker lifetime, independent of React rendering. No
// artifact bytes, keys, results or server operations are retained in this class.
export class RecordingRuntimeOwner {
    #slot: RuntimeSlot | null = null;
    #retired = false;

    constructor(
        private readonly owns: () => boolean,
        private readonly create: typeof createRecordingRuntime = createRecordingRuntime,
    ) {}

    async acquire(image: ReceivedArtifact, signal: AbortSignal): Promise<RecordingRuntime> {
        if (image.request.kind !== 'recording' || signal.aborted || this.#retired || !this.owns()) {
            throw new EvidenceError('cancelled');
        }
        const previous = this.#slot;
        if (
            previous &&
            previous.source === image.request.auditlog &&
            uuidEqual(previous.id, image.request.id) &&
            previous.value?.available()
        ) {
            return previous.value;
        }
        this.clear();
        const slot: RuntimeSlot = {
            source: image.request.auditlog,
            id: image.request.id,
            controller: new AbortController(),
            value: undefined,
        };
        this.#slot = slot;
        try {
            const value = await this.create(slot.source, slot.id, slot.controller.signal, signal);
            if (this.#slot !== slot || this.#retired || !this.owns() || signal.aborted) {
                value.dispose();
                throw new EvidenceError('cancelled');
            }
            slot.value = value;
            return value;
        } catch (error) {
            if (this.#slot === slot) {
                this.clear();
            }
            throw error;
        }
    }

    clear(): void {
        const slot = this.#slot;
        this.#slot = null;
        slot?.controller.abort();
        slot?.value?.dispose();
    }

    dispose(): void {
        this.#retired = true;
        this.clear();
    }
}
