import type { WebAccess } from '../remember';
import { SnapshotObservers } from '../shared/snapshot-observers';
import type { VerifiedArtifact } from './evidence-protocol';
import { EvidenceError } from './evidence-protocol';
import type { RecordingInfo } from './open-recording';
import type { EvidenceKey } from './verify';

export interface ArtifactSecretMetadata {
    readonly fingerprint: string | null;
    readonly revision: number;
}
const unavailable: ArtifactSecretMetadata = Object.freeze({ fingerprint: null, revision: 0 });

// Owned by one management tab, shared ONLY by its Recording/Audit pages. Never
// indexed by username/origin, persisted, serialized, or used for authentication.
export class ArtifactSessionSecrets {
    readonly #owner: WebAccess | undefined;
    #retired = false;
    #metadata: ArtifactSecretMetadata = unavailable;
    readonly #observers = new SnapshotObservers();
    readonly subscribe = this.#observers.subscribe;
    readonly getSnapshot = (): ArtifactSecretMetadata =>
        this.#usable() ? this.#metadata : unavailable;
    constructor(owner?: WebAccess) {
        this.#owner = owner;
    }
    #key: { file: Blob; passphrase: Uint8Array; fingerprint: string } | null = null;
    #usable(): boolean {
        return !this.#retired && this.#owner?.status() !== 'closed';
    }
    ownedBy(owner: WebAccess): boolean {
        return this.#owner === owner;
    }
    #publish(fingerprint: string | null): void {
        this.#metadata = Object.freeze({ fingerprint, revision: this.#metadata.revision + 1 });
        this.#observers.notify();
    }
    #replace(file: Blob, passphrase: Uint8Array, fingerprint: string): void {
        this.#key?.passphrase.fill(0);
        this.#key = { file, passphrase, fingerprint };
        this.#publish(fingerprint);
    }
    remember(key: EvidenceKey, verified: VerifiedArtifact): void {
        if (this.#retired || this.#owner?.status() === 'closed') {
            throw new EvidenceError('cancelled');
        }
        const metadata = verified.metadata;
        if (
            verified.provenance !== 'bytes-only' ||
            metadata.validation !== 'private' ||
            !['authenticated', 'no-private-records'].includes(metadata.decryption) ||
            !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(metadata.expectedRecipient) ||
            key.file.size < 1 ||
            key.file.size > 64 << 10
        ) {
            throw new EvidenceError('key');
        }
        const passphrase = new TextEncoder().encode(key.passphrase);
        if (passphrase.byteLength > 4096) {
            passphrase.fill(0);
            throw new EvidenceError('key');
        }
        this.#replace(key.file, passphrase, metadata.expectedRecipient);
    }
    matching(fingerprint: string): EvidenceKey | null {
        if (this.#retired || this.#owner?.status() === 'closed') {
            this.retire();
            return null;
        }
        const cached = this.#key;
        if (cached === null || cached.fingerprint !== fingerprint) {
            return null;
        }
        return { file: cached.file, passphrase: new TextDecoder().decode(cached.passphrase) };
    }
    rememberDecryption(key: EvidenceKey, info: RecordingInfo): void {
        if (this.#retired || this.#owner?.status() === 'closed') {
            throw new EvidenceError('cancelled');
        }
        if (
            !info.encrypted ||
            info.requiresKey ||
            info.decryption !== 'authenticated' ||
            !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(info.recipient) ||
            key.file.size < 1 ||
            key.file.size > 64 << 10
        ) {
            throw new EvidenceError('key');
        }
        const passphrase = new TextEncoder().encode(key.passphrase);
        if (passphrase.byteLength > 4096) {
            passphrase.fill(0);
            throw new EvidenceError('key');
        }
        this.#replace(key.file, passphrase, info.recipient);
    }
    has(fingerprint: string): boolean {
        return (
            this.#key?.fingerprint === fingerprint &&
            !this.#retired &&
            this.#owner?.status() !== 'closed'
        );
    }
    fingerprint(): string | null {
        return this.getSnapshot().fingerprint;
    }
    clear(): void {
        if (this.#key === null) {
            return;
        }
        this.#key?.passphrase.fill(0);
        this.#key = null;
        this.#publish(null);
    }
    retire(): void {
        this.#retired = true;
        this.clear();
    }
    toJSON(): object {
        return { available: this.#key !== null };
    }
}
