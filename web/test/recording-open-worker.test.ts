import { afterEach, describe, expect, it, vi } from 'vitest';
import { openRecording } from '../src/artifacts/open-recording';
import type { ReceivedArtifact } from '../src/artifacts/protocol';

const id = '34e34ab8-7457-4d88-a5e4-c57791775c3a';
const source: ReceivedArtifact = {
    request: { kind: 'recording', auditlog: 'default', id },
    transport: 'complete',
    evidence: 'unverified',
    metadata: { Version: 1, ID: id, ProducerID: 'a'.repeat(64), Size: 3, SHA256: 'b'.repeat(64) },
    files: [{ name: 'recording', data: new Blob([new Uint8Array([1, 2, 3])]) }],
};
class OpenWorker extends EventTarget {
    static instances: OpenWorker[] = [];
    static requiresKey = false;
    static forgedTrust = false;
    terminated = false;
    requests: Record<string, unknown>[] = [];
    constructor(url: string, config: WorkerOptions) {
        super();
        expect(url).toBe('/_bifroest/files/browser-evidence-worker.js');
        expect(config).toMatchObject({
            type: 'module',
            credentials: 'omit',
            name: 'bifroest-recording-open',
        });
        OpenWorker.instances.push(this);
        queueMicrotask(() => this.send({ kind: 'ready' }));
    }
    send(value: unknown) {
        if (!this.terminated) {
            this.dispatchEvent(new MessageEvent('message', { data: value }));
        }
    }
    postMessage(value: Record<string, unknown>, transfer: Transferable[]) {
        const body = structuredClone(value, { transfer });
        this.requests.push(body);
        expect(body.kind).toBe('open-recording');
        expect(Object.keys(body).sort()).toEqual([
            'data',
            'id',
            'kind',
            'passphrase',
            'privateKey',
        ]);
        const requiresKey = OpenWorker.requiresKey;
        queueMicrotask(() =>
            this.send({
                kind: 'opened',
                metadata: {
                    info: {
                        recordingId: id,
                        producer: 'a'.repeat(64),
                        recipient: requiresKey ? `SHA256:${'A'.repeat(43)}` : '',
                        encrypted: requiresKey,
                        requiresKey,
                        decryption: requiresKey ? 'not-checked' : 'not-encrypted',
                        flow: requiresKey ? '' : 'worker',
                        sessionId: '',
                    },
                    playback: requiresKey
                        ? null
                        : {
                              version: 1,
                              recordingId: id,
                              producer: 'a'.repeat(64),
                              trust: OpenWorker.forgedTrust ? 'pinned' : 'not-checked',
                              columns: 80,
                              rows: 24,
                              pty: false,
                              frames: 0,
                              durationUs: 0,
                              status: 'completed',
                              exitStatus: 0,
                          },
                },
                output: new ArrayBuffer(0),
            }),
        );
    }
    terminate() {
        this.terminated = true;
    }
}
afterEach(() => {
    vi.unstubAllGlobals();
    OpenWorker.instances = [];
    OpenWorker.requiresKey = false;
    OpenWorker.forgedTrust = false;
});
describe('owned recording decoder, without signature verification', () => {
    it('releases only explicitly unchecked playback and performs no main-thread HTTP or verify RPC', async () => {
        vi.stubGlobal('Worker', OpenWorker);
        const fetch = vi.fn();
        vi.stubGlobal('fetch', fetch);
        const result = await openRecording(source, null, new AbortController().signal);
        expect(result.image?.metadata.trust).toBe('not-checked');
        expect(result.info.decryption).toBe('not-encrypted');
        expect(fetch).not.toHaveBeenCalled();
        expect(OpenWorker.instances).toHaveLength(1);
        expect(OpenWorker.instances[0]?.requests).toHaveLength(1);
        expect(OpenWorker.instances[0]?.terminated).toBe(true);
        result.image?.dispose();
    });
    it('returns key requirements without plaintext or a signature result', async () => {
        vi.stubGlobal('Worker', OpenWorker);
        OpenWorker.requiresKey = true;
        const result = await openRecording(source, null, new AbortController().signal);
        expect(result.image).toBeNull();
        expect(result.info.requiresKey).toBe(true);
        expect(result.info.decryption).toBe('not-checked');
        expect(OpenWorker.instances).toHaveLength(1);
    });
    it('rejects a worker trying to promote decoded data to pinned evidence', async () => {
        vi.stubGlobal('Worker', OpenWorker);
        OpenWorker.forgedTrust = true;
        await expect(
            openRecording(source, null, new AbortController().signal),
        ).rejects.toMatchObject({
            code: 'protocol',
        });
        expect(OpenWorker.instances[0]?.terminated).toBe(true);
    });
    it('does not start or retry after cancellation or for oversized keys', async () => {
        vi.stubGlobal('Worker', OpenWorker);
        const stopped = new AbortController();
        stopped.abort();
        await expect(openRecording(source, null, stopped.signal)).rejects.toMatchObject({
            code: 'cancelled',
        });
        await expect(
            openRecording(
                source,
                { file: new Blob([new Uint8Array((64 << 10) + 1)]), passphrase: '' },
                new AbortController().signal,
            ),
        ).rejects.toMatchObject({ code: 'key' });
        expect(OpenWorker.instances).toHaveLength(0);
    });
});
