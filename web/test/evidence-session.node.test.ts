import { expect, it, vi } from 'vitest';
import { ArtifactSessionSecrets } from '../src/artifacts/artifact-secrets';
import { EvidenceSession, type EvidenceSessionBoundary } from '../src/artifacts/evidence-session';
import { matchesEvidenceTarget } from '../src/artifacts/evidence-target';
import type { PlaybackImage } from '../src/artifacts/playback-protocol';
import type { ReceivedArtifact } from '../src/artifacts/protocol';
import type { RecordingPreview } from '../src/artifacts/recording-preview';
import type { RecordingRuntime } from '../src/artifacts/verify';
import type { EvidenceVerificationOptions, verifyEvidence } from '../src/artifacts/verify-evidence';

const id = '00000000-0000-0000-0000-000000000001';
const artifact: ReceivedArtifact = {
    request: { kind: 'recording', auditlog: 'Original', id },
    transport: 'complete',
    evidence: 'unverified',
    metadata: { Version: 1, ID: id, ProducerID: 'a'.repeat(64), Size: 1, SHA256: '0'.repeat(64) },
    files: [{ name: 'recording', data: new Blob(['x']) }],
};
const options: EvidenceVerificationOptions = {
    expectation: { enabled: false, producer: '', source: 'reported' },
    level: 'private',
    auditScope: 'complete',
    sensitive: false,
    indexAudit: false,
};
function fixture() {
    const pending = Promise.withResolvers<ReceivedArtifact>();
    const boundary: EvidenceSessionBoundary = {
        accepts: () => true,
        owns: () => true,
        matches: () => true,
        target: () => null,
    };
    const runtime: RecordingRuntime = {
        available: () => true,
        receive: vi.fn(),
        verify: vi.fn(),
        open: vi.fn(),
        dispose: vi.fn(),
    };
    const preview =
        vi.fn<
            (
                ...args: Parameters<
                    typeof import('../src/artifacts/recording-preview').prepareRecordingPreview
                >
            ) => Promise<RecordingPreview | null>
        >();
    const verify = vi.fn<typeof verifyEvidence>();
    const owner = { acquire: vi.fn(async () => runtime), dispose: vi.fn() };
    const session = new EvidenceSession(
        { status: () => 'active', downloadArtifact: vi.fn(() => pending.promise) },
        boundary,
        { preview, verify, runtime: () => owner },
    );
    session.document.open(artifact.request);
    const failed = vi.fn();
    return {
        session,
        pending,
        boundary,
        preview,
        verify,
        owner,
        failed,
        keys: new ArtifactSessionSecrets(),
    };
}
it('receives one completed image and rejects a response whose exact route changed during transfer', async () => {
    const f = fixture();
    const task = f.session.job.run(
        'downloading',
        async (lease) => {
            await f.session.receive(artifact.request, lease);
        },
        f.failed,
        vi.fn(),
    );
    f.boundary.matches = () => false;
    f.pending.resolve(artifact);
    await task;
    expect(f.session.document.getSnapshot().received).toBeNull();
    expect(f.failed).toHaveBeenCalledWith(
        expect.objectContaining({ code: 'cancelled' }),
        'downloading',
    );
});
it('retiring a session prevents late transfer publication without changing the original bytes', async () => {
    const f = fixture();
    const task = f.session.job.run(
        'downloading',
        async (lease) => {
            await f.session.receive(artifact.request, lease);
        },
        f.failed,
        vi.fn(),
    );
    f.session.retire();
    f.pending.resolve(artifact);
    await task;
    expect(f.session.document.getSnapshot().opened).toBeNull();
    expect(f.session.document.getSnapshot().received).toBeNull();
    expect(await artifact.files[0]?.data.text()).toBe('x');
});
it('disposes a late decoded image rather than publishing it to a retired session', async () => {
    const f = fixture();
    f.session.document.receive(artifact);
    const pending = Promise.withResolvers<RecordingPreview | null>();
    f.preview.mockReturnValueOnce(pending.promise);
    const task = f.session.job.run(
        'preparing',
        async (lease) => {
            await f.session.prepare(artifact, null, f.keys, lease);
        },
        f.failed,
        vi.fn(),
    );
    await vi.waitFor(() => expect(f.preview).toHaveBeenCalledOnce());
    f.session.retire();
    const image = { metadata: { recordingId: id }, dispose: vi.fn() } as unknown as PlaybackImage;
    pending.resolve({
        kind: 'ready',
        image,
        source: new Blob(['x']),
        info: {
            recordingId: id,
            producer: 'a'.repeat(64),
            recipient: '',
            encrypted: false,
            requiresKey: false,
            decryption: 'not-encrypted',
            flow: 'Exact',
            sessionId: id,
        },
    });
    await task;
    expect(image.dispose).toHaveBeenCalledOnce();
    expect(f.owner.dispose).toHaveBeenCalledOnce();
    expect(f.session.document.getSnapshot().playback).toBeNull();
});
it('keeps expectation/private-field options unchanged and owns verified receipt publication', async () => {
    const f = fixture();
    f.session.document.receive(artifact);
    const completed: Awaited<ReturnType<typeof verifyEvidence>> = {
        expectation: options.expectation,
        auditIndex: null,
        context: { flow: 'Exact', sessionId: id },
        verified: {
            request: artifact.request,
            provenance: 'bytes-only',
            output: null,
            metadata: {
                kind: 'recording',
                validation: 'outer',
                trust: 'untrusted',
                producer: 'a'.repeat(64),
                expectedRecipient: '',
                decryption: 'not-checked',
                recordingId: id,
                auditScope: '',
                records: '1',
                privateRecords: '0',
                outputFormat: '',
            },
        },
    };
    f.verify.mockResolvedValueOnce(completed);
    await f.session.job.run(
        'verifying',
        async (lease) => {
            await f.session.verify(
                artifact,
                { producer: 'a'.repeat(64), expectedRecipient: '' },
                null,
                options,
                f.keys,
                lease,
            );
        },
        f.failed,
        vi.fn(),
    );
    expect(f.verify.mock.calls[0]?.[3]).toBe(options);
    expect(f.session.document.getSnapshot().receipt.verified).toBe(completed.verified);
    expect(f.failed).not.toHaveBeenCalled();
});
it('matches source names exactly while comparing recording IDs by UUID bytes', () => {
    expect(
        matchesEvidenceTarget(
            artifact.request,
            { page: 'recordings', auditlogHint: 'original', id },
            false,
        ),
    ).toBe(false);
    expect(
        matchesEvidenceTarget(
            artifact.request,
            { page: 'recordings', auditlogHint: 'Original', id },
            false,
        ),
    ).toBe(true);
    expect(matchesEvidenceTarget(artifact.request, null, false)).toBe(false);
    expect(matchesEvidenceTarget(artifact.request, null, true)).toBe(true);
});
