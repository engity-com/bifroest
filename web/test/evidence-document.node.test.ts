import { expect, it, vi } from 'vitest';
import { EvidenceDocument } from '../src/artifacts/evidence-document';
import type { VerifiedArtifact } from '../src/artifacts/evidence-protocol';
import type { PlaybackImage } from '../src/artifacts/playback-protocol';
import type { ReceivedArtifact } from '../src/artifacts/protocol';

const id = '00000000-0000-0000-0000-000000000001';
const artifact: ReceivedArtifact = {
    request: { kind: 'recording', auditlog: 'Original', id },
    transport: 'complete',
    evidence: 'unverified',
    metadata: { Version: 1, ID: id, ProducerID: 'a'.repeat(64), Size: 1, SHA256: '0'.repeat(64) },
    files: [{ name: 'recording', data: new Blob(['x']) }],
};
const result: VerifiedArtifact = {
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
};
function image(recordingId = id) {
    return { metadata: { recordingId }, dispose: vi.fn() } as unknown as PlaybackImage;
}
it('retires every source-derived field atomically when another source is opened', () => {
    const document = new EvidenceDocument();
    document.open(artifact.request);
    document.receive(artifact);
    document.inspect(result.metadata);
    document.information({
        recordingId: id,
        producer: 'a'.repeat(64),
        recipient: '',
        encrypted: false,
        requiresKey: false,
        decryption: 'not-encrypted',
        flow: 'Exact.Flow',
        sessionId: id,
    });
    document.updateReceipt({
        type: 'verified',
        value: result,
        index: null,
        sensitive: false,
        expectation: { enabled: false, producer: '', source: 'reported' },
        flow: 'Exact.Flow',
        session: id,
    });
    const prepared = image();
    document.preview(new Blob(['x']), prepared);
    const observer = vi.fn();
    document.subscribe(observer);
    document.open({ kind: 'audit', auditlog: 'Other' });
    expect(observer).toHaveBeenCalledOnce();
    const next = document.getSnapshot();
    expect(next.received).toBeNull();
    expect(next.protection).toBeNull();
    expect(next.recordingInfo).toBeNull();
    expect(next.playback).toBeNull();
    expect(next.receipt.verified).toBeNull();
    expect(next.receipt.recordingFlow).toBe('');
    expect(prepared.dispose).toHaveBeenCalledOnce();
});
it('rejects a foreign source receipt and disposes an unpublishable preview', () => {
    const document = new EvidenceDocument();
    document.open({ ...artifact.request, auditlog: 'Other' });
    expect(() => document.receive(artifact)).toThrow();
    document.open(artifact.request);
    document.receive(artifact);
    const wrong = image('00000000-0000-0000-0000-000000000002');
    expect(() => document.preview(new Blob(['x']), wrong)).toThrow();
    expect(wrong.dispose).toHaveBeenCalledOnce();
    expect(document.getSnapshot().playback).toBeNull();
    document.close();
    expect(() =>
        document.updateReceipt({
            type: 'verified',
            value: result,
            index: null,
            sensitive: false,
            expectation: { enabled: false, producer: '', source: 'reported' },
            flow: '',
            session: '',
        }),
    ).toThrow();
});
it('does not retain byte-derived data or dispose renderer-owned bytes after closing the document', () => {
    const document = new EvidenceDocument();
    document.open(artifact.request);
    document.receive(artifact);
    const prepared = image();
    document.preview(new Blob(['x']), prepared);
    const playback = document.getSnapshot().playback;
    if (!playback) {
        throw new Error('Missing preparation');
    }
    expect(playback.image.take()).toBe(prepared);
    document.close();
    expect(prepared.dispose).not.toHaveBeenCalled();
    expect(document.getSnapshot().received).toBeNull();
    prepared.dispose();
});

it('accepts exactly one completed image per open, never keeping an old receipt for replacement bytes', () => {
    const document = new EvidenceDocument();
    document.open(artifact.request);
    document.receive(artifact);
    document.updateReceipt({
        type: 'verified',
        value: result,
        index: null,
        sensitive: false,
        expectation: { enabled: false, producer: '', source: 'reported' },
        flow: '',
        session: '',
    });
    const original = document.getSnapshot();
    const replacement = {
        ...artifact,
        files: [{ name: 'recording', data: new Blob(['OTHER-BYTES']) }],
    };
    expect(() => document.receive(replacement)).toThrow();
    expect(() => document.receive(artifact)).toThrow();
    expect(document.getSnapshot()).toBe(original);
    document.open(artifact.request);
    expect(document.getSnapshot().receipt.verified).toBeNull();
    document.receive(replacement);
    expect(document.getSnapshot().received).toBe(replacement);
});
