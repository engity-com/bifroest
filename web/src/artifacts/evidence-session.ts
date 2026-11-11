import type { WebAccess } from '../remember/client';
import type { OperationLease } from '../shared/operation';
import type { ArtifactSessionSecrets } from './artifact-secrets';
import { EvidenceDocument } from './evidence-document';
import { EvidenceJob } from './evidence-job';
import { EvidenceError, type EvidenceMetadata } from './evidence-protocol';
import { readEvidenceKey } from './local-key-input';
import type { LocalKeySelection } from './local-key-input-view';
import { inspectProtection } from './protection';
import { type ArtifactRequest, artifactFields, type ReceivedArtifact } from './protocol';
import { type LocalRecordingIndex, recordingVerificationFromIndex } from './recording-index';
import { prepareRecordingPreview } from './recording-preview';
import { RecordingRuntimeOwner } from './recording-runtime-owner';
import type { EvidenceKey, RecordingRuntime } from './verify';
import { type EvidenceVerificationOptions, verifyEvidence } from './verify-evidence';

export interface EvidenceSessionBoundary {
    accepts(request: ArtifactRequest): boolean;
    owns(): boolean;
    matches(request: ArtifactRequest): boolean;
    target(): { readonly flow?: string; readonly sessionId?: string } | null;
}
interface EvidenceServices {
    verify: typeof verifyEvidence;
    preview: typeof prepareRecordingPreview;
    runtime(): Pick<RecordingRuntimeOwner, 'acquire' | 'dispose'>;
}

// A local evidence session owns all byte-derived resources and publication.
// Dialogs, URLs, DOM inputs, credentials and rendering are not part of its state.
export class EvidenceSession {
    readonly document: EvidenceDocument;
    readonly job: EvidenceJob;
    #runtime: Pick<RecordingRuntimeOwner, 'acquire' | 'dispose'> | null = null;
    constructor(
        private readonly access: Pick<WebAccess, 'status' | 'downloadArtifact'>,
        private readonly boundary: EvidenceSessionBoundary,
        private readonly services: EvidenceServices = {
            verify: verifyEvidence,
            preview: prepareRecordingPreview,
            runtime: () => new RecordingRuntimeOwner(() => boundary.owns()),
        },
    ) {
        this.document = new EvidenceDocument((request) => boundary.accepts(request));
        this.job = new EvidenceJob(() => this.document.getSnapshot().opened !== null);
    }
    current(lease: OperationLease): boolean {
        return (
            lease.current() &&
            !lease.signal.aborted &&
            this.access.status() !== 'closed' &&
            this.boundary.owns()
        );
    }
    clearRuntime(): void {
        const runtime = this.#runtime;
        this.#runtime = null;
        runtime?.dispose();
    }
    retire(): void {
        try {
            this.clearRuntime();
        } finally {
            try {
                this.job.retire();
            } finally {
                this.document.close();
            }
        }
    }
    async runtime(image: ReceivedArtifact, signal: AbortSignal): Promise<RecordingRuntime> {
        this.#runtime ??= this.services.runtime();
        return this.#runtime.acquire(image, signal);
    }
    async reuseSourceReceipt(
        image: ReceivedArtifact,
        index: LocalRecordingIndex | null,
        stillSelected: () => boolean,
        lease: OperationLease,
    ): Promise<boolean> {
        const cached = await recordingVerificationFromIndex(index, image, lease.signal);
        if (
            !cached ||
            !stillSelected() ||
            !this.current(lease) ||
            !this.boundary.matches(image.request)
        ) {
            return false;
        }
        this.document.updateReceipt({
            type: 'verified',
            value: cached.verified,
            index: null,
            sensitive: false,
            expectation: {
                enabled: cached.verified.metadata.trust === 'pinned',
                producer:
                    cached.verified.metadata.trust === 'pinned'
                        ? cached.verified.metadata.producer
                        : '',
                source: cached.reported ? 'reported' : 'user',
            },
            flow: cached.verified.metadata.recordingContext?.flow ?? '',
            session: cached.verified.metadata.recordingContext?.sessionId ?? '',
        });
        return true;
    }
    async receive(
        request: ArtifactRequest,
        lease: OperationLease,
    ): Promise<ReceivedArtifact | null> {
        artifactFields(request);
        const image = await this.access.downloadArtifact(request, lease.signal, (value) => {
            if (this.current(lease)) {
                this.job.progress(lease, value);
            }
        });
        if (!this.current(lease)) {
            return null;
        }
        if (!this.boundary.matches(request)) {
            throw new EvidenceError('cancelled');
        }
        this.document.receive(image);
        return image;
    }
    async inspect(
        image: ReceivedArtifact,
        options: {
            reuse: boolean;
            level: 'outer' | 'private';
            auditScope: 'complete' | 'captured-prefix';
            selection: LocalKeySelection | null;
        },
        keys: ArtifactSessionSecrets,
        lease: OperationLease,
    ) {
        const local = this.document.getSnapshot();
        const header =
            options.reuse && image.request.kind === 'recording' && local.recordingInfo
                ? {
                      producer: local.recordingInfo.producer,
                      expectedRecipient: local.recordingInfo.recipient,
                  }
                : ((options.reuse ? local.protection : null) ??
                  (await inspectProtection(image, lease.signal, options.auditScope, (value) => {
                      if (this.current(lease)) {
                          this.job.progress(lease, value);
                      }
                  })));
        if (!this.current(lease)) {
            return null;
        }
        if ('validation' in header) {
            this.document.inspect(header);
        }
        let key =
            options.level === 'outer' || header.expectedRecipient === ''
                ? null
                : keys.matching(header.expectedRecipient);
        if (options.level === 'private' && options.selection?.file) {
            if (header.expectedRecipient === '' && options.reuse) {
                throw new EvidenceError('key');
            }
            if (header.expectedRecipient !== '') {
                key = await readEvidenceKey(
                    options.selection.file,
                    options.selection.passphrase,
                    lease.signal,
                );
            }
        }
        if (options.level === 'private' && header.expectedRecipient !== '' && key === null) {
            throw new EvidenceError('key-required');
        }
        return this.current(lease) ? { header, key } : null;
    }
    async unlock(
        image: ReceivedArtifact,
        selection: LocalKeySelection,
        keys: ArtifactSessionSecrets,
        lease: OperationLease,
    ) {
        const info = this.document.getSnapshot().recordingInfo;
        let key = info?.encrypted ? keys.matching(info.recipient) : null;
        if (selection.file) {
            key = await readEvidenceKey(selection.file, selection.passphrase, lease.signal);
        }
        if (!this.current(lease)) {
            return null;
        }
        this.document.clearPlayback();
        return this.prepare(image, key, keys, lease);
    }
    async verify(
        image: ReceivedArtifact,
        header: Pick<EvidenceMetadata, 'producer' | 'expectedRecipient'>,
        key: EvidenceKey | null,
        options: EvidenceVerificationOptions,
        keys: ArtifactSessionSecrets,
        lease: OperationLease,
    ) {
        const completed = await this.services.verify(image, header, key, options, {
            signal: lease.signal,
            current: () => this.current(lease),
            matches: () => this.boundary.matches(image.request),
            target: () => this.boundary.target(),
            recording: (source, signal) => this.runtime(source, signal),
            progress: (value) => this.job.progress(lease, value),
        });
        // Publishing and cache writes belong to this lease, not to a later React
        // effect or a caller's interpretation of a completed worker promise.
        if (!this.current(lease) || !this.boundary.matches(image.request)) {
            return null;
        }
        if (key !== null) {
            keys.remember(key, completed.verified);
        }
        if (!this.current(lease) || !this.boundary.matches(image.request)) {
            return null;
        }
        this.document.updateReceipt({ type: 'invalidate-verification' });
        if (!this.current(lease) || !this.boundary.matches(image.request)) {
            return null;
        }
        this.document.updateReceipt({
            type: 'verified',
            value: completed.verified,
            index: completed.auditIndex,
            sensitive: options.sensitive,
            expectation: completed.expectation,
            flow: completed.context.flow,
            session: completed.context.sessionId,
        });
        return completed;
    }
    async prepare(
        image: ReceivedArtifact,
        key: EvidenceKey | null,
        keys: ArtifactSessionSecrets,
        lease: OperationLease,
    ) {
        this.job.progress(lease, null);
        const runtime = await this.runtime(image, lease.signal);
        const result = await this.services.preview(runtime, image, key, {
            signal: lease.signal,
            current: () => this.current(lease),
            target: () => this.boundary.target(),
            keys,
            information: this.document.information,
        });
        if (!this.current(lease) || !this.boundary.matches(image.request)) {
            if (result?.kind === 'ready') {
                result.image.dispose();
            }
            return null;
        }
        if (result?.kind === 'ready') {
            this.document.preview(result.source, result.image);
        }
        return result;
    }
}
