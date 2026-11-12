import type { RecordingSummary } from '../management/protocol';
import { SnapshotObservers } from '../shared/snapshot-observers';
import { uuidEqual } from '../shared/uuid';
import { EvidenceError, type EvidenceMetadata } from './evidence-protocol';
import {
    type EvidenceResult,
    type EvidenceResultEvent,
    emptyEvidenceResult,
    evidenceResultTransition,
} from './evidence-result';
import type { RecordingInfo } from './open-recording';
import type { PlaybackImage } from './playback-protocol';
import { PreparedPlayback } from './prepared-playback';
import type { ArtifactRequest, ReceivedArtifact } from './protocol';

export interface EvidenceDocumentState {
    readonly opened: ArtifactRequest | null;
    readonly selection: RecordingSummary | null;
    readonly received: ReceivedArtifact | null;
    readonly protection: EvidenceMetadata | null;
    readonly recordingInfo: RecordingInfo | null;
    readonly playback: { readonly source: Blob; readonly image: PreparedPlayback } | null;
    readonly receipt: EvidenceResult;
}
const empty = (): EvidenceDocumentState => ({
    opened: null,
    selection: null,
    received: null,
    protection: null,
    recordingInfo: null,
    playback: null,
    receipt: emptyEvidenceResult(),
});
function sameRequest(a: ArtifactRequest | null, b: ArtifactRequest): boolean {
    return (
        a !== null &&
        a.kind === b.kind &&
        a.auditlog === b.auditlog &&
        (a.kind === 'audit' || (b.kind === 'recording' && uuidEqual(a.id, b.id)))
    );
}

// One local document, separate from execution leases and dialog preferences.
// Source changes retire all byte-derived state together. No network, key cache,
// React effect or browser route can be initiated by this owner.
export class EvidenceDocument {
    constructor(private readonly accepts: (request: ArtifactRequest) => boolean = () => true) {}
    #state = empty();
    readonly #observers = new SnapshotObservers();
    readonly getSnapshot = () => this.#state;
    readonly subscribe = this.#observers.subscribe;
    #publish(state: EvidenceDocumentState): void {
        const previous = this.#state;
        this.#state = Object.freeze(state);
        if (previous.playback !== state.playback) {
            previous.playback?.image.dispose();
        }
        this.#observers.notify();
    }
    open(request: ArtifactRequest, summary?: RecordingSummary): void {
        if (!this.accepts(request)) {
            throw new EvidenceError('cancelled');
        }
        this.#publish({
            ...empty(),
            opened: Object.freeze({ ...request }),
            selection: summary ?? null,
            receipt: evidenceResultTransition(emptyEvidenceResult(), {
                type: 'relation',
                flow: summary?.flow ?? '',
                session: summary?.sessionId ?? '',
            }),
        });
    }
    close(): void {
        this.#publish(empty());
    }
    receive(image: ReceivedArtifact): void {
        if (!this.accepts(image.request) || !sameRequest(this.#state.opened, image.request)) {
            throw new EvidenceError('input');
        }
        // A receipt belongs to one immutable completed image. Another receive,
        // even for the same selector, requires an explicit new open operation.
        if (this.#state.received !== null) {
            throw new EvidenceError('input');
        }
        this.#publish({ ...this.#state, received: image });
    }
    inspect(metadata: EvidenceMetadata): void {
        if (!this.#state.received) {
            throw new EvidenceError('cancelled');
        }
        this.#publish({ ...this.#state, protection: metadata });
    }
    forgetProtection(): void {
        this.#publish({ ...this.#state, protection: null });
    }
    readonly information = (info: RecordingInfo): void => {
        const request = this.#state.received?.request;
        if (request?.kind !== 'recording' || !uuidEqual(request.id, info.recordingId)) {
            throw new EvidenceError('input');
        }
        this.#publish({ ...this.#state, recordingInfo: Object.freeze({ ...info }) });
    };
    preview(source: Blob, image: PlaybackImage): void {
        const request = this.#state.received?.request;
        if (request?.kind !== 'recording' || !uuidEqual(request.id, image.metadata.recordingId)) {
            image.dispose();
            throw new EvidenceError('input');
        }
        this.#publish({ ...this.#state, playback: { source, image: new PreparedPlayback(image) } });
    }
    clearPlayback(): void {
        if (this.#state.playback) {
            this.#publish({ ...this.#state, playback: null });
        }
    }
    readonly updateReceipt = (event: EvidenceResultEvent): void => {
        if (
            event.type === 'verified' &&
            (!this.#state.received || !sameRequest(this.#state.opened, event.value.request))
        ) {
            throw new EvidenceError('input');
        }
        this.#publish({
            ...this.#state,
            receipt: evidenceResultTransition(this.#state.receipt, event),
        });
    };
}
