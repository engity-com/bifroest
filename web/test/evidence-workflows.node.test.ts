import { expect, it, vi } from 'vitest';
import type { VerifiedArtifact } from '../src/artifacts/evidence-protocol';
import { emptyEvidenceResult, evidenceResultTransition } from '../src/artifacts/evidence-result';
import type { ReceivedArtifact } from '../src/artifacts/protocol';
import { verifyRecordingSource } from '../src/artifacts/recording-source-verification';
import type { RecordingVerificationBatch } from '../src/artifacts/verify';
import { verifyEvidence } from '../src/artifacts/verify-evidence';
import type { RecordingSourceImages } from '../src/management/source-transfer';

const id = '00000000-0000-0000-0000-000000000001';
const session = '00000000-0000-0000-0000-000000000002';
const producer = 'a'.repeat(64);
const artifact: ReceivedArtifact = {
    request: { kind: 'recording', auditlog: 'Exact.Source', id },
    transport: 'complete',
    evidence: 'unverified',
    metadata: { Version: 1, ID: id, ProducerID: producer, Size: 1, SHA256: '0'.repeat(64) },
    files: [{ name: 'fixture', data: new Blob(['x']) }],
};
const verified: VerifiedArtifact = {
    request: artifact.request,
    provenance: 'bytes-only',
    metadata: {
        kind: 'recording',
        validation: 'private',
        trust: 'pinned',
        producer,
        expectedRecipient: '',
        decryption: 'not-encrypted',
        recordingId: id,
        auditScope: '',
        records: '1',
        privateRecords: '1',
        outputFormat: 'cast',
    },
    output: new Blob([
        `# bifroest:metadata:v1 ${JSON.stringify({ recordingId: id, flow: 'Exact.Flow', sessionId: session })}\n`,
    ]),
};
const expectation = { enabled: true, producer, source: 'user' as const };
it('keeps exact verified recording selectors and trust options in the DOM-independent verification use case', async () => {
    const check = vi.fn(async () => verified);
    const result = await verifyEvidence(
        artifact,
        { producer, expectedRecipient: '' },
        null,
        {
            expectation,
            level: 'private',
            auditScope: 'complete',
            sensitive: false,
            indexAudit: false,
        },
        {
            signal: new AbortController().signal,
            current: () => true,
            matches: () => true,
            target: () => ({ flow: 'Exact.Flow', sessionId: session }),
            recording: async () => ({ verify: check }),
            progress: vi.fn(),
        },
    );
    expect(result.context).toEqual({ flow: 'Exact.Flow', sessionId: session });
    expect(check).toHaveBeenCalledWith(
        artifact,
        expect.objectContaining({
            producer,
            allowUntrusted: false,
            level: 'private',
            sensitive: false,
        }),
        null,
        expect.any(Function),
        expect.any(AbortSignal),
    );
});
it.each([
    { flow: 'exact.flow', sessionId: session },
    { flow: 'Exact.Flow', sessionId: id },
])('rejects a changed exact selection after byte verification: %j', async (target) => {
    await expect(
        verifyEvidence(
            artifact,
            { producer, expectedRecipient: '' },
            null,
            {
                expectation,
                level: 'private',
                auditScope: 'complete',
                sensitive: false,
                indexAudit: false,
            },
            {
                signal: new AbortController().signal,
                current: () => true,
                matches: () => true,
                target: () => target,
                recording: async () => ({ verify: async () => verified }),
                progress: vi.fn(),
            },
        ),
    ).rejects.toMatchObject({ code: 'verification' });
});
it('never publishes the result of a worker that completed for a retired owner', async () => {
    let owned = true;
    await expect(
        verifyEvidence(
            artifact,
            { producer, expectedRecipient: '' },
            null,
            {
                expectation,
                level: 'private',
                auditScope: 'complete',
                sensitive: false,
                indexAudit: false,
            },
            {
                signal: new AbortController().signal,
                current: () => owned,
                matches: () => true,
                target: () => null,
                recording: async () => ({
                    verify: async () => {
                        owned = false;
                        return verified;
                    },
                }),
                progress: vi.fn(),
            },
        ),
    ).rejects.toMatchObject({ code: 'cancelled' });
});
it('owns source-stream and worker cleanup on failure without exposing a partial verification receipt', async () => {
    const iterator = (async function* () {
        yield {
            request: artifact.request,
            image: { bytes: new ArrayBuffer(0), mediaType: '', status: 200 },
            index: 0,
            total: 1,
            encrypted: false,
            recipient: '',
        };
    })();
    const stream: RecordingSourceImages = Object.assign(iterator, {
        closed: Promise.resolve(),
        cancel: vi.fn(),
    });
    const close = vi.spyOn(stream, 'return');
    const batch: RecordingVerificationBatch = {
        receive: vi.fn(async () => artifact),
        verify: vi.fn(async () => {
            throw new Error('Verification failure');
        }),
        dispose: vi.fn(),
    };
    await expect(
        verifyRecordingSource(
            { source: 'Exact.Source', level: 'outer', producer, reported: false, key: null },
            {
                signal: new AbortController().signal,
                current: () => true,
                progress: vi.fn(),
                keys: { matching: vi.fn(), remember: vi.fn() },
                open: async () => stream,
                createBatch: async () => batch,
            },
        ),
    ).rejects.toThrow('Verification failure');
    expect(batch.dispose).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalled();
});
it('atomically invalidates a verification receipt and private projection without mutating the previous receipt', () => {
    const receipt = evidenceResultTransition(emptyEvidenceResult(), {
        type: 'verified',
        value: verified,
        index: null,
        sensitive: true,
        expectation,
        flow: 'Exact.Flow',
        session,
    });
    const invalidated = evidenceResultTransition(receipt, { type: 'invalidate-verification' });
    expect(invalidated.verified).toBeNull();
    expect(invalidated.used).toBeNull();
    expect(invalidated.verifiedSensitive).toBe(false);
    expect(invalidated.recordingFlow).toBe('Exact.Flow');
    expect(receipt.verified).toBe(verified);
    expect(evidenceResultTransition(receipt, { type: 'clear' }).recordingSession).toBe('');
});
