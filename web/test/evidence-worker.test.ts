import { afterEach, describe, expect, it, vi } from 'vitest';
import type { EvidenceOptions } from '../src/artifacts/evidence-protocol';
import type { ReceivedArtifact } from '../src/artifacts/protocol';
import { verifyArtifact } from '../src/artifacts/verify';
import { required } from './required';

const id = '34e34ab8-7457-4d88-a5e4-c57791775c3a';
const artifact: ReceivedArtifact = {
  request: { kind: 'recording', auditlog: 'default', id },
  transport: 'complete',
  evidence: 'unverified',
  metadata: { Version: 1, ID: id, ProducerID: 'b'.repeat(64), Size: 3, SHA256: 'c'.repeat(64) },
  files: [{ name: 'recording', data: new Blob([new Uint8Array([1, 2, 3])]) }],
};
const options: EvidenceOptions = {
  producer: 'a'.repeat(64),
  allowUntrusted: false,
  recipient: '',
  level: 'private',
  export: true,
  sensitive: false,
  auditScope: '',
};

class EvidenceWorker extends EventTarget {
  static instances: EvidenceWorker[] = [];
  static hold = false;
  static badProducer = false;
  static failure: 'key' | 'verification' | null = null;
  terminated = false;
  requests: Record<string, unknown>[] = [];

  constructor(url: string, config: WorkerOptions) {
    super();
    expect(url).toBe('/_bifroest/files/browser-evidence-worker.js');
    expect(config).toMatchObject({ type: 'module', credentials: 'omit' });
    EvidenceWorker.instances.push(this);
    queueMicrotask(() => this.send({ kind: 'ready' }));
  }
  send(value: unknown) {
    if (!this.terminated) {
      this.dispatchEvent(new MessageEvent('message', { data: value }));
    }
  }
  postMessage(value: Record<string, unknown>, transfer: Transferable[]) {
    this.requests.push(value);
    const body = structuredClone(value, { transfer });
    if (EvidenceWorker.hold) {
      return;
    }
    queueMicrotask(() => {
      if (EvidenceWorker.failure !== null) {
        this.send({ kind: 'failed', code: EvidenceWorker.failure });
        return;
      }
      const input = body.options as EvidenceOptions;
      this.send({
        kind: 'verified',
        metadata: {
          kind: 'recording',
          validation: input.level,
          trust: input.producer === '' ? 'untrusted' : 'pinned',
          producer: EvidenceWorker.badProducer ? 'b'.repeat(64) : input.producer || 'a'.repeat(64),
          expectedRecipient: input.recipient,
          decryption: input.recipient === '' ? 'not-encrypted' : 'authenticated',
          recordingId: id,
          auditScope: '',
          records: '0',
          privateRecords: '0',
          outputFormat: input.export ? 'cast' : '',
        },
        output: new Blob(input.export ? ['verified cast'] : []),
      });
    });
  }
  terminate() {
    this.terminated = true;
  }
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
  EvidenceWorker.instances = [];
  EvidenceWorker.hold = false;
  EvidenceWorker.badProducer = false;
  EvidenceWorker.failure = null;
});

describe('owned evidence worker RPC (not cryptographic fixture verification)', () => {
  it('uses caller pins rather than untrusted transport hints and retires before returning output', async () => {
    vi.stubGlobal('Worker', EvidenceWorker);
    const result = await verifyArtifact(artifact, options, null, new AbortController().signal);
    expect(result.metadata.producer).toBe(options.producer);
    expect(result.metadata.producer).not.toBe('b'.repeat(64));
    expect(result.provenance).toBe('bytes-only');
    expect(await result.output?.text()).toBe('verified cast');
    const worker = required(EvidenceWorker.instances[0]);
    expect(worker.terminated).toBe(true);
    expect(worker.requests).toHaveLength(1);
    expect(JSON.stringify(worker.requests)).not.toContain('bwa1.');
    expect(Object.isFrozen(result)).toBe(true);
  });

  it('rejects missing independent pins, incomplete transport and unwanted keys before any worker', async () => {
    vi.stubGlobal('Worker', EvidenceWorker);
    for (const input of [
      { artifact, options: { ...options, producer: '' }, key: null },
      { artifact: { ...artifact, transport: 'data-end' }, options, key: null },
      { artifact, options: { ...options, level: 'outer' }, key: null },
      { artifact, options, key: { file: new File(['key'], 'private'), passphrase: '' } },
    ]) {
      await expect(
        verifyArtifact(
          input.artifact as ReceivedArtifact,
          input.options as EvidenceOptions,
          input.key,
          new AbortController().signal,
        ),
      ).rejects.toMatchObject({ code: 'input' });
    }
    expect(EvidenceWorker.instances).toHaveLength(0);
  });

  it('keeps explicit untrusted state distinct and never promotes a worker producer mismatch', async () => {
    vi.stubGlobal('Worker', EvidenceWorker);
    const untrusted = await verifyArtifact(
      artifact,
      { ...options, producer: '', allowUntrusted: true },
      null,
      new AbortController().signal,
    );
    expect(untrusted.metadata.trust).toBe('untrusted');
    EvidenceWorker.badProducer = true;
    await expect(
      verifyArtifact(artifact, options, null, new AbortController().signal),
    ).rejects.toMatchObject({ code: 'verification' });
    expect(required(EvidenceWorker.instances.at(-1)).terminated).toBe(true);
  });

  it('transfers local key buffers only to the evidence worker and reports no parser diagnostics', async () => {
    vi.stubGlobal('Worker', EvidenceWorker);
    EvidenceWorker.failure = 'key';
    await expect(
      verifyArtifact(
        artifact,
        { ...options, recipient: `SHA256:${'A'.repeat(43)}` },
        {
          file: new File(['private tab bytes'], 'never-uploaded-key'),
          passphrase: 'private tab password',
        },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ code: 'key' });
    const worker = required(EvidenceWorker.instances[0]);
    const request = required(worker.requests[0]);
    expect((request.privateKey as ArrayBuffer).byteLength).toBe(0);
    expect((request.passphrase as ArrayBuffer).byteLength).toBe(0);
    expect(JSON.stringify(request)).not.toContain('private tab password');
    expect(JSON.stringify(request)).not.toContain('never-uploaded-key');
    expect(worker.terminated).toBe(true);
  });

  it('cancels a pending local key read and never starts verification with partial private input', async () => {
    vi.stubGlobal('Worker', EvidenceWorker);
    let entered: (() => void) | undefined;
    const reading = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let aborted = false;
    class HeldReader {
      onload = null;
      onerror = null;
      onabort = null;
      result = null;
      readAsArrayBuffer() {
        entered?.();
      }
      abort() {
        aborted = true;
      }
    }
    vi.stubGlobal('FileReader', HeldReader);
    const controller = new AbortController();
    const operation = verifyArtifact(
      artifact,
      { ...options, recipient: `SHA256:${'A'.repeat(43)}` },
      { file: new File(['key'], 'private'), passphrase: 'secret' },
      controller.signal,
    );
    const observed = expect(operation).rejects.toMatchObject({ code: 'cancelled' });
    await reading;
    controller.abort();
    await observed;
    expect(aborted).toBe(true);
    expect(required(EvidenceWorker.instances[0]).requests).toHaveLength(0);
    expect(required(EvidenceWorker.instances[0]).terminated).toBe(true);
  });

  it('kills a non-answering crypto worker at its hard deadline without releasing a Blob', async () => {
    vi.stubGlobal('Worker', EvidenceWorker);
    EvidenceWorker.hold = true;
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    vi.spyOn(AbortSignal, 'timeout').mockImplementation((milliseconds) => {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), milliseconds);
      return controller.signal;
    });
    const operation = verifyArtifact(artifact, options, null, new AbortController().signal);
    const observed = expect(operation).rejects.toMatchObject({ code: 'unavailable' });
    await vi.waitFor(() => expect(EvidenceWorker.instances[0]?.requests.length).toBe(1));
    await vi.advanceTimersByTimeAsync(120_001);
    await observed;
    expect(required(EvidenceWorker.instances[0]).terminated).toBe(true);
  });
});
