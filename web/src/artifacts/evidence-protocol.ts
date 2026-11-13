import { recordingTime } from '../management/protocol';
import { object } from '../remember/http';
import { resourceID, uuidEqual } from '../shared/uuid';
import type { ArtifactRequest } from './protocol';

export class EvidenceError extends Error {
    constructor(
        readonly code:
            | 'input'
            | 'key'
            | 'key-required'
            | 'limit'
            | 'verification'
            | 'cancelled'
            | 'unavailable'
            | 'worker'
            | 'worker-timeout'
            | 'module-fetch'
            | 'module-decode'
            | 'runtime'
            | 'protocol',
    ) {
        super(`Client evidence: ${code}`);
        this.name = 'EvidenceError';
    }
}

export interface EvidenceOptions {
    readonly producer: string;
    readonly allowUntrusted: boolean;
    readonly recipient: string;
    readonly recipientFromKey?: boolean;
    readonly recipientFromHeader?: boolean;
    readonly level: 'outer' | 'private';
    readonly export: boolean;
    readonly sensitive: boolean;
    readonly auditScope: '' | 'complete' | 'captured-prefix';
    readonly metadata?: boolean;
}

export interface EvidenceMetadata {
    readonly kind: 'recording' | 'audit';
    readonly validation: 'outer' | 'private';
    readonly trust: 'pinned' | 'untrusted';
    readonly producer: string;
    readonly expectedRecipient: string;
    readonly decryption: 'not-checked' | 'not-encrypted' | 'authenticated' | 'no-private-records';
    readonly recordingId: string;
    readonly auditScope: '' | 'complete' | 'captured-prefix';
    readonly records: string;
    readonly privateRecords: string;
    readonly outputFormat: '' | 'cast' | 'jsonl';
    readonly recordingContext?: RecordingContext;
}
export interface RecordingContext {
    readonly flow: string;
    readonly sessionId: string;
    readonly user: string;
    readonly startedAt: string;
    readonly endedAt: string;
    readonly status: 'completed' | 'failed' | 'incomplete';
    readonly chunkCount: number;
}

export interface VerifiedArtifact {
    readonly request: ArtifactRequest;
    readonly provenance: 'bytes-only';
    readonly metadata: EvidenceMetadata;
    readonly output: Blob | null;
}

export function evidenceOptions(request: ArtifactRequest, value: unknown): EvidenceOptions {
    try {
        const body = object(value, [
            'producer',
            'allowUntrusted',
            'recipient',
            'level',
            'export',
            'sensitive',
            'auditScope',
            ...(value !== null && typeof value === 'object' && Object.hasOwn(value, 'metadata')
                ? ['metadata']
                : []),
            ...(value !== null &&
            typeof value === 'object' &&
            Object.hasOwn(value, 'recipientFromKey')
                ? ['recipientFromKey']
                : []),
            ...(value !== null &&
            typeof value === 'object' &&
            Object.hasOwn(value, 'recipientFromHeader')
                ? ['recipientFromHeader']
                : []),
        ]);
        if (
            typeof body.producer !== 'string' ||
            (body.producer !== '' &&
                (!/^[0-9a-f]{64}$/u.test(body.producer) || /^0+$/u.test(body.producer))) ||
            typeof body.allowUntrusted !== 'boolean' ||
            (body.producer === '' && !body.allowUntrusted) ||
            typeof body.recipient !== 'string' ||
            (body.recipientFromHeader !== undefined &&
                (typeof body.recipientFromHeader !== 'boolean' ||
                    (body.recipientFromHeader &&
                        (request.kind !== 'recording' ||
                            body.level !== 'outer' ||
                            body.recipient !== '' ||
                            body.recipientFromKey)))) ||
            (body.recipientFromKey !== undefined &&
                (typeof body.recipientFromKey !== 'boolean' ||
                    (body.recipientFromKey &&
                        (body.level !== 'private' || body.recipient !== '')))) ||
            (body.recipient !== '' && !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(body.recipient)) ||
            (body.level !== 'outer' && body.level !== 'private') ||
            typeof body.export !== 'boolean' ||
            typeof body.sensitive !== 'boolean' ||
            ((body.export || body.sensitive) && body.level !== 'private') ||
            (request.kind === 'recording' && (body.sensitive || body.auditScope !== '')) ||
            (body.metadata !== undefined &&
                (typeof body.metadata !== 'boolean' ||
                    (body.metadata &&
                        (request.kind !== 'recording' || body.level !== 'private')))) ||
            (request.kind === 'audit' &&
                body.auditScope !== 'complete' &&
                body.auditScope !== 'captured-prefix')
        ) {
            throw new Error();
        }
        return Object.freeze({ ...body }) as unknown as EvidenceOptions;
    } catch {
        throw new EvidenceError('input');
    }
}

export function evidenceMetadata(
    request: ArtifactRequest,
    options: EvidenceOptions,
    value: unknown,
): EvidenceMetadata {
    try {
        const body = object(value, [
            'kind',
            'validation',
            'trust',
            'producer',
            'expectedRecipient',
            'decryption',
            'recordingId',
            'auditScope',
            'records',
            'privateRecords',
            'outputFormat',
            ...(value !== null &&
            typeof value === 'object' &&
            Object.hasOwn(value, 'recordingContext')
                ? ['recordingContext']
                : []),
        ]);
        if (
            body.kind !== request.kind ||
            (body.validation !== 'outer' && body.validation !== 'private') ||
            (options.level === 'private' && body.validation !== 'private') ||
            (body.trust !== 'pinned' && body.trust !== 'untrusted') ||
            typeof body.producer !== 'string' ||
            !/^[0-9a-f]{64}$/u.test(body.producer) ||
            (options.producer !== '' &&
                (body.producer !== options.producer || body.trust !== 'pinned')) ||
            (options.producer === '' && body.trust !== 'untrusted') ||
            (options.recipientFromHeader
                ? typeof body.expectedRecipient !== 'string' ||
                  (body.expectedRecipient !== '' &&
                      !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(body.expectedRecipient))
                : options.recipientFromKey
                  ? typeof body.expectedRecipient !== 'string' ||
                    !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(body.expectedRecipient)
                  : body.expectedRecipient !== options.recipient) ||
            typeof body.decryption !== 'string' ||
            !['not-checked', 'not-encrypted', 'authenticated', 'no-private-records'].includes(
                body.decryption,
            ) ||
            (request.kind === 'recording'
                ? !uuidEqual(body.recordingId, request.id)
                : body.recordingId !== '') ||
            body.auditScope !== options.auditScope ||
            typeof body.records !== 'string' ||
            !/^(0|[1-9][0-9]{0,19})$/u.test(body.records) ||
            typeof body.privateRecords !== 'string' ||
            !/^(0|[1-9][0-9]{0,19})$/u.test(body.privateRecords) ||
            BigInt(body.privateRecords) > BigInt(body.records) ||
            body.outputFormat !==
                (options.export ? (request.kind === 'recording' ? 'cast' : 'jsonl') : '') ||
            (body.decryption === 'authenticated' &&
                (options.level !== 'private' ||
                    (options.recipient === '' && !options.recipientFromKey))) ||
            (body.decryption === 'not-encrypted' &&
                (options.recipient !== '' || options.recipientFromKey))
        ) {
            throw new Error();
        }
        let context: RecordingContext | undefined;
        if (body.recordingContext !== undefined) {
            if (
                !options.metadata ||
                request.kind !== 'recording' ||
                body.validation !== 'private' ||
                !['authenticated', 'not-encrypted'].includes(String(body.decryption))
            ) {
                throw new Error();
            }
            const raw = object(body.recordingContext, [
                'flow',
                'sessionId',
                'user',
                'startedAt',
                'endedAt',
                'status',
                'chunkCount',
            ]);
            if (
                typeof raw.flow !== 'string' ||
                !/^[A-Za-z0-9.-]{1,255}$/u.test(raw.flow) ||
                ['.', '..'].includes(raw.flow) ||
                !resourceID(raw.sessionId) ||
                typeof raw.user !== 'string' ||
                new TextEncoder().encode(raw.user).byteLength > 256 ||
                !raw.user.isWellFormed() ||
                /[\p{Cc}]/u.test(raw.user) ||
                !['completed', 'failed', 'incomplete'].includes(String(raw.status)) ||
                !Number.isSafeInteger(raw.chunkCount) ||
                Number(raw.chunkCount) < 1 ||
                Number(raw.chunkCount) > 2 ** 18
            ) {
                throw new Error();
            }
            const started = recordingTime(raw.startedAt);
            const ended = recordingTime(raw.endedAt);
            if (Date.parse(ended) < Date.parse(started)) {
                throw new Error();
            }
            context = Object.freeze({
                ...raw,
                startedAt: started,
                endedAt: ended,
            }) as unknown as RecordingContext;
        } else if (options.metadata) {
            throw new Error();
        }
        if (context) {
            return Object.freeze({
                ...body,
                recordingContext: context,
            }) as unknown as EvidenceMetadata;
        }
        return Object.freeze({ ...body }) as unknown as EvidenceMetadata;
    } catch {
        throw new EvidenceError('verification');
    }
}
