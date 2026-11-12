import { describe, expect, it } from 'vitest';
import { ArtifactSessionSecrets } from '../src/artifacts/artifact-secrets';
import type { VerifiedArtifact } from '../src/artifacts/evidence-protocol';
import type { WebAccess } from '../src/remember';

const fingerprint = `SHA256:${'A'.repeat(43)}`;
const verified: VerifiedArtifact = {
    request: { kind: 'recording', auditlog: 'default', id: '34e34ab8-7457-4d88-a5e4-c57791775c3a' },
    provenance: 'bytes-only',
    output: new Blob(['verified output']),
    metadata: {
        kind: 'recording',
        validation: 'private',
        trust: 'untrusted',
        producer: 'a'.repeat(64),
        expectedRecipient: fingerprint,
        decryption: 'authenticated',
        recordingId: '34e34ab8-7457-4d88-a5e4-c57791775c3a',
        auditScope: '',
        records: '0',
        privateRecords: '0',
        outputFormat: 'cast',
    },
};
describe('volatile actor-tab decryption key reuse', () => {
    it('reuses only a verified key for its own public fingerprint, without serialization or storage', async () => {
        const cache = new ArtifactSessionSecrets();
        const key = {
            file: new Blob(['PRIVATE-KEY-SENTINEL']),
            passphrase: 'PRIVATE-PASSPHRASE-SENTINEL',
        };
        cache.remember(key, verified);
        expect(cache.has(fingerprint)).toBe(true);
        expect(cache.matching(fingerprint)?.passphrase).toBe(key.passphrase);
        expect(await cache.matching(fingerprint)?.file.text()).toBe('PRIVATE-KEY-SENTINEL');
        expect(cache.matching(`SHA256:${'B'.repeat(43)}`)).toBeNull();
        expect(JSON.stringify(cache)).toBe('{"available":true}');
        cache.clear();
        expect(cache.matching(fingerprint)).toBeNull();
        expect(cache.fingerprint()).toBeNull();
    });
    it('does not replace a good key with an unverified candidate, or share it with another tab', () => {
        const first = new ArtifactSessionSecrets();
        const second = new ArtifactSessionSecrets();
        const key = { file: new Blob(['PRIVATE']), passphrase: 'correct' };
        first.remember(key, verified);
        expect(() =>
            first.remember(
                { file: new Blob(['WRONG']), passphrase: 'wrong' },
                { ...verified, metadata: { ...verified.metadata, decryption: 'not-checked' } },
            ),
        ).toThrow();
        expect(first.matching(fingerprint)?.passphrase).toBe('correct');
        expect(second.matching(fingerprint)).toBeNull();
    });
    it('retirement and authoritative logout reject late successful-worker writes', () => {
        let state: 'active' | 'closed' = 'active';
        const owner = { status: () => state } as WebAccess;
        const cache = new ArtifactSessionSecrets(owner);
        const key = { file: new Blob(['PRIVATE']), passphrase: 'secret' };
        cache.remember(key, verified);
        state = 'closed';
        expect(cache.matching(fingerprint)).toBeNull();
        expect(() => cache.remember(key, verified)).toThrow();
        const retired = new ArtifactSessionSecrets();
        retired.retire();
        expect(() => retired.remember(key, verified)).toThrow();
        expect(retired.has(fingerprint)).toBe(false);
    });
});
