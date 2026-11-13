import { expect, it } from 'vitest';
import { evidenceMetadata, type VerifiedArtifact } from '../src/artifacts/evidence-protocol';
import type { ReceivedArtifact } from '../src/artifacts/protocol';
import {
    isLocalRecordingMetadata,
    localRecordingPage,
    maximumLocalRecordings,
    RecordingIndexBuilder,
    recordingByteDigest,
    recordingVerificationFromIndex,
} from '../src/artifacts/recording-index';
import { uuidText } from '../src/shared/uuid';

const session = '82d8fdda-4730-43b7-bfde-72733c217bde';
function fixture(
    number = 1,
    source = 'source',
): { image: ReceivedArtifact; verified: VerifiedArtifact } {
    const id = `00000000-0000-4000-8000-${number.toString(16).padStart(12, '0')}`;
    const request = { kind: 'recording' as const, auditlog: source, id };
    const producer = 'a'.repeat(64);
    const recipient = `SHA256:${'a'.repeat(43)}`;
    const metadata = evidenceMetadata(
        request,
        {
            producer,
            allowUntrusted: false,
            recipient,
            level: 'private',
            export: false,
            sensitive: false,
            auditScope: '',
            metadata: true,
        },
        {
            kind: 'recording',
            validation: 'private',
            trust: 'pinned',
            producer,
            expectedRecipient: recipient,
            decryption: 'authenticated',
            recordingId: id,
            auditScope: '',
            records: '0',
            privateRecords: '0',
            outputFormat: '',
            recordingContext: {
                flow: 'docker',
                sessionId: session,
                user: 'private-user',
                startedAt: '2026-11-05T00:00:00Z',
                endedAt: '2026-11-05T00:00:01Z',
                status: 'completed',
                chunkCount: 2,
            },
        },
    );
    return {
        image: {
            request,
            transport: 'complete',
            evidence: 'unverified',
            metadata: {
                Version: 1,
                ID: id,
                ProducerID: producer,
                Size: 100,
                SHA256: 'b'.repeat(64),
            },
            files: [{ name: 'recording', data: new Blob(['opaque']) }],
        },
        verified: { request, provenance: 'bytes-only', metadata, output: null },
    };
}
it('publishes metadata without keys or plaintext, redacts until the private eye is enabled and filters exact binary selectors locally', () => {
    const builder = new RecordingIndexBuilder('source');
    const { image, verified } = fixture();
    builder.add(image, verified);
    const index = builder.finish();
    const hidden = localRecordingPage(index, 0, '', null, true, false);
    expect(hidden.total).toBe(1);
    expect(hidden.items[0]?.user).toBeUndefined();
    expect(hidden.items[0]?.flow).toBeUndefined();
    expect(hidden.items[0]?.sessionId).toBeUndefined();
    expect(localRecordingPage(index, 0, 'private-user', null, true, false).total).toBe(0);
    expect(localRecordingPage(index, 0, '', null, true, false, 'docker', session).total).toBe(0);
    const shown = localRecordingPage(
        index,
        0,
        '',
        { field: 'user', operator: 'equals', value: 'private-user' },
        true,
        true,
        'docker',
        uuidText(session),
    );
    expect(shown.total).toBe(1);
    expect(shown.items[0]).toMatchObject({
        user: 'private-user',
        flow: 'docker',
        sessionId: session,
        encrypted: true,
    });
    expect(shown.items[0]?.target).toBeUndefined();
    expect(
        localRecordingPage(
            index,
            0,
            '',
            { field: 'target', operator: 'isEmpty', value: '' },
            true,
            true,
        ).total,
    ).toBe(0);
    expect(isLocalRecordingMetadata(shown.items[0])).toBe(true);
    expect(
        localRecordingPage(
            index,
            0,
            '',
            { field: 'sessionId', operator: 'equals', value: uuidText(session) },
            true,
            true,
        ).total,
    ).toBe(1);
    expect(localRecordingPage(index, 0, '', null, true, true, 'other', session).total).toBe(0);
    expect(JSON.stringify(index)).not.toContain('opaque');
    expect(JSON.stringify(index)).not.toContain('passphrase');
    expect(() =>
        localRecordingPage(
            index,
            0,
            '',
            { field: 'user', operator: 'bogus', value: 'x' },
            true,
            true,
        ),
    ).toThrow();
    builder.clear();
    expect(shown.items[0]?.user).toBe('private-user');
    expect(() => builder.finish()).toThrow();
});
it('retains server page boundaries with ascending UUID byte ties in both chronological directions', () => {
    const builder = new RecordingIndexBuilder('source');
    for (let number = 21; number >= 1; number--) {
        const { image, verified } = fixture(number);
        const request = {
            kind: 'recording' as const,
            auditlog: 'source',
            id:
                number % 2
                    ? uuidText(verified.metadata.recordingId)
                    : verified.metadata.recordingId,
        };
        builder.add({ ...image, request }, { ...verified, request });
    }
    const index = builder.finish();
    const expected = Array.from({ length: 21 }, (_, number) =>
        uuidText(fixture(number + 1).verified.metadata.recordingId),
    );
    for (const descending of [false, true]) {
        const first = localRecordingPage(index, 0, '', null, descending, false);
        const last = localRecordingPage(index, 1, '', null, descending, false);
        expect(first.items.map((row) => uuidText(row.id))).toEqual(expected.slice(0, 20));
        expect(last.items.map((row) => uuidText(row.id))).toEqual(expected.slice(20));
        expect(first.total).toBe(21);
        expect(last.total).toBe(21);
    }
});

it('fails closed for outer-only evidence, unauthenticated decryption, foreign sources and duplicate notation aliases', () => {
    for (const change of ['outer', 'not-checked', 'foreign', 'duplicate']) {
        const builder = new RecordingIndexBuilder('source');
        const { image, verified } = fixture();
        if (change === 'outer') {
            expect(() =>
                builder.add(image, {
                    ...verified,
                    metadata: { ...verified.metadata, validation: 'outer' },
                }),
            ).toThrow();
        } else if (change === 'not-checked') {
            expect(() =>
                builder.add(image, {
                    ...verified,
                    metadata: { ...verified.metadata, decryption: 'not-checked' },
                }),
            ).toThrow();
        } else if (change === 'foreign') {
            expect(() =>
                builder.add(
                    { ...image, request: { ...image.request, auditlog: 'foreign' } },
                    verified,
                ),
            ).toThrow();
        } else {
            builder.add(image, verified);
            const alias = {
                kind: 'recording' as const,
                auditlog: 'source',
                id: uuidText(verified.metadata.recordingId),
            };
            expect(() =>
                builder.add({ ...image, request: alias }, { ...verified, request: alias }),
            ).toThrow();
        }
        expect(() => builder.finish()).toThrow();
    }
});

it('reuses a completed full verdict only for identical source, UUID, digest, size and producer bytes', async () => {
    const { image, verified } = fixture();
    const bytes = new Blob([new Uint8Array(100)]);
    const signal = new AbortController().signal;
    const digest = await recordingByteDigest(
        { ...image, files: [{ name: 'recording', data: bytes }] },
        signal,
    );
    const owned = {
        ...image,
        metadata: { ...image.metadata, SHA256: digest },
        files: [{ name: 'recording', data: bytes }],
    };
    const builder = new RecordingIndexBuilder('source', false);
    builder.add(owned, verified, digest);
    const index = builder.finish();
    const reused = await recordingVerificationFromIndex(index, owned, signal);
    expect(reused?.verified.metadata).toMatchObject({
        validation: 'private',
        decryption: 'authenticated',
        producer: verified.metadata.producer,
    });
    expect(reused?.reported).toBe(false);
    expect(reused?.verified.output).toBeNull();
    const metadata = owned.metadata;
    if (!('SHA256' in metadata)) {
        throw new Error('Missing recording fixture');
    }
    for (const changed of [
        {
            ...owned,
            request: {
                kind: 'recording' as const,
                auditlog: 'other',
                id: verified.metadata.recordingId,
            },
        },
        { ...owned, metadata: { ...metadata, SHA256: 'c'.repeat(64) } },
        { ...owned, metadata: { ...metadata, Size: 99 } },
        { ...owned, metadata: { ...metadata, ProducerID: 'd'.repeat(64) } },
        { ...owned, files: [{ name: 'recording', data: new Blob(['changed']) }] },
        { ...owned, files: [{ name: 'recording', data: new Blob([new Uint8Array(100).fill(1)]) }] },
    ]) {
        expect(await recordingVerificationFromIndex(index, changed, signal)).toBeNull();
    }
    expect(await recordingVerificationFromIndex(null, owned, signal)).toBeNull();
    expect(await recordingVerificationFromIndex({ ...index }, owned, signal)).toBeNull();
    await expect(recordingByteDigest(owned, AbortSignal.abort())).rejects.toThrow();
});
it('enforces both metadata byte and object-count bounds without publishing a partial index', () => {
    const { image, verified } = fixture();
    const builder = new RecordingIndexBuilder('source');
    for (let number = 1; number <= maximumLocalRecordings; number++) {
        const id = `00000000-0000-4000-8000-${number.toString(16).padStart(12, '0')}`;
        const request = { kind: 'recording' as const, auditlog: 'source', id };
        builder.add(
            { ...image, request },
            { ...verified, request, metadata: { ...verified.metadata, recordingId: id } },
        );
    }
    const extra = fixture(maximumLocalRecordings + 1);
    expect(() => builder.add(extra.image, extra.verified)).toThrow();
    expect(() => builder.finish()).toThrow();
    const largeSource = 's'.repeat(128);
    const large = new RecordingIndexBuilder(largeSource);
    let rejectedAt = 0;
    for (let number = 1; number <= maximumLocalRecordings; number++) {
        const row = fixture(number, largeSource);
        const original = row.verified.metadata.recordingContext;
        if (!original) {
            throw new Error('Missing fixture recording context');
        }
        const context = {
            ...original,
            flow: 'f'.repeat(255),
            user: 'ü'.repeat(128),
        };
        try {
            large.add(row.image, {
                ...row.verified,
                metadata: { ...row.verified.metadata, recordingContext: context },
            });
        } catch {
            rejectedAt = number;
            break;
        }
    }
    expect(rejectedAt).toBeGreaterThan(1000);
    expect(rejectedAt).toBeLessThan(maximumLocalRecordings);
    expect(() => large.finish()).toThrow();
});
