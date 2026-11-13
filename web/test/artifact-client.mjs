import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { chromium } from 'playwright';

const [origin, mode, keyPath] = process.argv.slice(2);
assert.match(origin, /^https:\/\/app\.example\.org:[0-9]+$/u);
assert(
    [
        'normal',
        'encrypted',
        'held-success',
        'held-failure',
        'source-held-success',
        'source-held-failure',
        'source-cancel',
    ].includes(mode),
);
const privateBytes = keyPath ? [...readFileSync(keyPath)] : [];
const browser = await chromium.launch({
    headless: true,
    args: ['--host-resolver-rules=MAP app.example.org 127.0.0.1', '--no-proxy-server'],
});
try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    await context.addCookies([
        { name: 'unrelated', value: 'must-not-authenticate', url: origin, secure: true },
    ]);
    const page = await context.newPage();
    const errors = [];
    const privateRequests = [];
    const responses = [];
    const networkFailures = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('requestfailed', (request) => {
        networkFailures.push({
            path: new URL(request.url()).pathname,
            method: request.method(),
            error: request.failure()?.errorText,
        });
    });
    page.on('response', (response) => {
        const path = new URL(response.url()).pathname;
        if (path.includes('/management/artifacts/')) {
            const headers = response.headers();
            responses.push({
                path,
                status: response.status(),
                mediaType: headers['content-type'],
                encoding: headers['content-encoding'],
                length: headers['content-length'],
            });
        }
    });
    page.on('request', (request) => {
        const body = request.postData() ?? '';
        if (
            body.includes('PRIVATE KEY') ||
            body.includes('tab fixture secret') ||
            body.includes('wrong tab secret')
        ) {
            privateRequests.push(new URL(request.url()).pathname);
        }
    });
    const response = await page.goto(`${origin}/_bifroest/test/client.html`);
    assert.equal(response.status(), 200);
    assert(!response.headers()['content-security-policy'].includes('wasm-unsafe-eval'));
    const policies = await page.evaluate(async () => {
        const worker = await fetch('/_bifroest/files/browser-transfer-worker.js', {
            credentials: 'omit',
        });
        const ordinary = await fetch('/_bifroest/files/go-wasm-exec.js', { credentials: 'omit' });
        return {
            workerStatus: worker.status,
            worker: worker.headers.get('Content-Security-Policy'),
            ordinary: ordinary.headers.get('Content-Security-Policy'),
        };
    });
    assert.equal(policies.workerStatus, 200);
    assert(policies.worker.includes('wasm-unsafe-eval'));
    assert(!policies.ordinary.includes('wasm-unsafe-eval'));
    const result = await page
        .evaluate(
            async ({ mode, privateBytes }) => {
                const { BrowserClient, verifyArtifact, createRecordingVerificationBatch } =
                    await import('/_bifroest/test/client.js');
                const violations = [];
                window.addEventListener('securitypolicyviolation', (event) =>
                    violations.push(event.violatedDirective),
                );
                const WorkerType = window.Worker;
                const workers = [];
                window.Worker = class extends WorkerType {
                    constructor(url, options) {
                        super(url, options);
                        this.terminated = false;
                        this.requests = [];
                        workers.push(this);
                    }
                    postMessage(value, transfer) {
                        this.requests.push(JSON.stringify(value));
                        return super.postMessage(value, transfer);
                    }
                    terminate() {
                        this.terminated = true;
                        return super.terminate();
                    }
                };
                const client = new BrowserClient({ origin: location.origin, slug: 'Work' });
                const access = await client.password('alice', 'correct');
                await access.managementFlows();
                const entry = await fetch('/_bifroest/test/artifact-id', {
                    credentials: 'omit',
                }).then((response) => response.json());
                const selected = { kind: 'recording', auditlog: 'default', id: entry.id };
                if (mode.startsWith('source-')) {
                    const channel = access.openManagement(() => {});
                    await access.managementFlows();
                    const batch = await createRecordingVerificationBatch(
                        'default',
                        new AbortController().signal,
                    );
                    if (mode !== 'source-cancel') {
                        await fetch('/_bifroest/test/artifact-arm', {
                            method: 'POST',
                            credentials: 'omit',
                        });
                    }
                    const stream = await access.openRecordingSource('default');
                    if (mode === 'source-cancel') {
                        stream.cancel();
                        await stream.closed;
                        const after = await stream.next().then(
                            () => 'unexpected success',
                            (error) => error.code,
                        );
                        if (after !== 'cancelled') {
                            throw new Error('cancelled source resumed or reported success');
                        }
                        await access.managementFlows();
                    } else {
                        let settled = false;
                        const operation = stream.next().then(
                            (value) => {
                                settled = true;
                                return { value };
                            },
                            (error) => {
                                settled = true;
                                return { error: error.code };
                            },
                        );
                        await fetch('/_bifroest/test/artifact-entered', { credentials: 'omit' });
                        if (settled) {
                            throw new Error(
                                'source released a file before its final audit/capture completed',
                            );
                        }
                        await fetch('/_bifroest/test/artifact-release', {
                            method: 'POST',
                            credentials: 'omit',
                        });
                        const completed = await operation;
                        if (mode === 'source-held-failure') {
                            if (
                                completed.error !== 'unavailable' ||
                                completed.value !== undefined
                            ) {
                                throw new Error(
                                    'source released provisional bytes after final-audit failure',
                                );
                            }
                            await stream.closed;
                        } else {
                            if (!completed.value || completed.value.done) {
                                throw new Error('source did not release its completed file');
                            }
                            const row = completed.value.value;
                            const original = row.image.bytes.slice(0);
                            const received = await batch.receive(row.request, row.image);
                            if (
                                received.transport !== 'complete' ||
                                received.request.id !== row.request.id ||
                                received.metadata.ID !== row.request.id
                            ) {
                                throw new Error(
                                    'source transfer bypassed native selector/completion validation',
                                );
                            }
                            const ids = new Set([received.request.id]);
                            let count = 1;
                            for await (const remaining of stream) {
                                const next = await batch.receive(
                                    remaining.request,
                                    remaining.image,
                                );
                                if (ids.has(next.request.id) || remaining.total !== row.total) {
                                    throw new Error('source inventory changed during transfer');
                                }
                                ids.add(next.request.id);
                                count++;
                            }
                            if (count !== row.total || !ids.has(entry.id)) {
                                throw new Error(
                                    'source omitted an inventoried recording or completed early',
                                );
                            }
                            for (const variant of ['truncated', 'trailing', 'selector']) {
                                const input =
                                    variant === 'truncated'
                                        ? original.slice(0, -1)
                                        : variant === 'trailing'
                                          ? new Uint8Array([...new Uint8Array(original), 0]).buffer
                                          : original.slice(0);
                                const decoder = await createRecordingVerificationBatch(
                                    'default',
                                    new AbortController().signal,
                                );
                                const request =
                                    variant === 'selector'
                                        ? {
                                              ...row.request,
                                              id: '6d05798f-b877-4191-8aa0-4576a30411ad',
                                          }
                                        : row.request;
                                const code = await decoder
                                    .receive(request, { ...row.image, bytes: input })
                                    .then(
                                        () => 'unexpected success',
                                        (error) => error.code,
                                    );
                                if (code !== 'input' || !workers.at(-1).terminated) {
                                    throw new Error(
                                        `native source receiver accepted ${variant} without exact completion and EOF`,
                                    );
                                }
                            }
                            new Uint8Array(original).fill(0);
                        }
                    }
                    batch.dispose();
                    channel.disconnect();
                } else if (mode !== 'normal' && mode !== 'encrypted') {
                    await fetch('/_bifroest/test/artifact-arm', {
                        method: 'POST',
                        credentials: 'omit',
                    });
                    let settled = false;
                    const operation = access.downloadArtifact(selected).then(
                        (value) => {
                            settled = true;
                            return { value };
                        },
                        (error) => {
                            settled = true;
                            return { error: error.code };
                        },
                    );
                    await fetch('/_bifroest/test/artifact-entered', { credentials: 'omit' });
                    if (settled) {
                        throw new Error('DataEnd was exposed as successful artifact completion');
                    }
                    await fetch('/_bifroest/test/artifact-release', {
                        method: 'POST',
                        credentials: 'omit',
                    });
                    const completed = await operation;
                    if (mode === 'held-failure') {
                        if (completed.error !== 'unavailable' || completed.value !== undefined) {
                            throw new Error(
                                'a failed final audit released provisional artifact data',
                            );
                        }
                    } else if (
                        completed.value?.transport !== 'complete' ||
                        completed.value?.evidence !== 'unverified'
                    ) {
                        throw new Error('successful audited completion was not decoded by Go');
                    }
                } else {
                    const recording = await access.downloadArtifact(selected);
                    if (
                        recording.transport !== 'complete' ||
                        recording.evidence !== 'unverified' ||
                        recording.files.length !== 1
                    ) {
                        throw new Error('transport must not imply evidence trust or decryption');
                    }
                    const bytes = await recording.files[0].data.arrayBuffer();
                    const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
                        .map((value) => value.toString(16).padStart(2, '0'))
                        .join('');
                    if (
                        digest !== recording.metadata.SHA256 ||
                        recording.metadata.ID !== entry.id
                    ) {
                        throw new Error(
                            'recording sink bytes or selectors differ from the completed transfer',
                        );
                    }
                    const key =
                        mode === 'encrypted'
                            ? {
                                  file: new File(
                                      [new Uint8Array(privateBytes)],
                                      'local-offline-key',
                                  ),
                                  passphrase: 'tab fixture secret',
                              }
                            : null;
                    const expected = {
                        producer: entry.producer,
                        allowUntrusted: false,
                        recipient: mode === 'encrypted' ? entry.recipient : '',
                        level: 'outer',
                        export: false,
                        sensitive: false,
                        auditScope: '',
                    };
                    const outer = await verifyArtifact(
                        recording,
                        expected,
                        null,
                        new AbortController().signal,
                    );
                    if (
                        outer.metadata.trust !== 'pinned' ||
                        outer.metadata.validation !== 'outer' ||
                        outer.output !== null
                    ) {
                        throw new Error(
                            'outer authentication must remain separate from private verification/export',
                        );
                    }
                    const verified = await verifyArtifact(
                        recording,
                        { ...expected, level: 'private', export: true },
                        key,
                        new AbortController().signal,
                    );
                    if (
                        verified.metadata.validation !== 'private' ||
                        verified.metadata.trust !== 'pinned' ||
                        !(verified.output instanceof Blob) ||
                        verified.output.size === 0 ||
                        verified.metadata.decryption !==
                            (mode === 'encrypted' ? 'authenticated' : 'not-encrypted')
                    ) {
                        throw new Error(
                            'the local evidence worker did not independently verify/decrypt the recording',
                        );
                    }
                    const exported = await verified.output.text();
                    if (
                        !exported.startsWith('{"version":3,') ||
                        !exported.includes('# bifroest:signature:v1 ')
                    ) {
                        throw new Error('recording export was not the verified native Cast export');
                    }
                    const bad = await verifyArtifact(
                        recording,
                        { ...expected, producer: 'a'.repeat(64), level: 'private', export: true },
                        key,
                        new AbortController().signal,
                    ).then(
                        () => 'unexpected success',
                        (error) => error.code,
                    );
                    if (bad !== 'verification') {
                        throw new Error(
                            'a wrong independent producer pin released verified output',
                        );
                    }
                    if (key !== null) {
                        const wrong = await verifyArtifact(
                            recording,
                            { ...expected, level: 'private', export: true },
                            { ...key, passphrase: 'wrong tab secret' },
                            new AbortController().signal,
                        ).then(
                            () => 'unexpected success',
                            (error) => error.code,
                        );
                        if (wrong !== 'key') {
                            throw new Error('a wrong local passphrase released plaintext');
                        }
                    }
                    const audit = await access.downloadArtifact({
                        kind: 'audit',
                        auditlog: 'default',
                    });
                    if (
                        audit.transport !== 'complete' ||
                        audit.evidence !== 'unverified' ||
                        audit.metadata.Name !== 'default'
                    ) {
                        throw new Error(
                            'audit transport was not decoded as provisional-trust data',
                        );
                    }
                    if (
                        !audit.files.some((file) => file.name === 'head.cbor') ||
                        audit.files.length !== audit.metadata.Files.length
                    ) {
                        throw new Error('audit sink omitted a declared immutable file');
                    }
                    const auditVerified = await verifyArtifact(
                        audit,
                        { ...expected, level: 'private', export: true, auditScope: 'complete' },
                        key,
                        new AbortController().signal,
                    );
                    if (
                        auditVerified.metadata.trust !== 'pinned' ||
                        auditVerified.metadata.validation !== 'private' ||
                        auditVerified.metadata.outputFormat !== 'jsonl' ||
                        !(auditVerified.output instanceof Blob)
                    ) {
                        throw new Error(
                            'the local evidence worker did not verify the audit byte inventory',
                        );
                    }
                    const lines = await auditVerified.output.text();
                    if (lines.includes('"flow"') || lines.includes('"sessionId"')) {
                        throw new Error('redacted audit export exposed private correlation fields');
                    }
                    const batchStart = workers.length;
                    const batch = await createRecordingVerificationBatch(
                        'default',
                        new AbortController().signal,
                    );
                    const batchOptions = { ...expected, level: 'private', export: false };
                    const first = await batch.verify(recording, batchOptions, key);
                    const second = await batch.verify(recording, batchOptions, key);
                    if (
                        workers.length !== batchStart + 1 ||
                        first.output !== null ||
                        second.output !== null ||
                        first.metadata.trust !== 'pinned' ||
                        second.metadata.trust !== 'pinned' ||
                        first.metadata.decryption !==
                            (mode === 'encrypted' ? 'authenticated' : 'not-encrypted')
                    ) {
                        throw new Error(
                            'the source-bound runtime did not independently verify both complete inputs',
                        );
                    }
                    const changed = new Uint8Array(await recording.files[0].data.arrayBuffer());
                    changed[changed.length - 1] ^= 1;
                    const altered = {
                        ...recording,
                        files: [{ name: 'recording', data: new Blob([changed]) }],
                    };
                    const invalid = await batch.verify(altered, batchOptions, key).then(
                        () => 'unexpected success',
                        (error) => error.code,
                    );
                    changed.fill(0);
                    if (
                        invalid !== 'verification' ||
                        !workers[batchStart].terminated ||
                        workers[batchStart].requests.length !== 4
                    ) {
                        throw new Error(
                            'a repeated recording ID reused verification or released changed bytes',
                        );
                    }
                    const afterFailure = await batch.verify(recording, batchOptions, key).then(
                        () => 'unexpected success',
                        (error) => error.code,
                    );
                    if (afterFailure !== 'cancelled' || workers.length !== batchStart + 1) {
                        throw new Error('a failed batch restarted itself');
                    }
                    const foreignStart = workers.length;
                    const foreign = await createRecordingVerificationBatch(
                        'default',
                        new AbortController().signal,
                    );
                    const wrongSource = await foreign
                        .verify(
                            { ...recording, request: { ...recording.request, auditlog: 'other' } },
                            batchOptions,
                            key,
                        )
                        .then(
                            () => 'unexpected success',
                            (error) => error.code,
                        );
                    if (
                        wrongSource !== 'input' ||
                        !workers[foreignStart].terminated ||
                        workers[foreignStart].requests.length !== 1
                    ) {
                        throw new Error(
                            'a batch accepted a foreign source or transferred its key before source validation',
                        );
                    }
                }
                if (
                    workers.some(
                        (worker) =>
                            !worker.terminated ||
                            worker.requests.some((message) => message.includes('bwa1.')),
                    )
                ) {
                    throw new Error(
                        'an owned transport worker survived or received an authentication bearer',
                    );
                }
                if (
                    localStorage.length !== 0 ||
                    sessionStorage.length !== 0 ||
                    violations.length !== 0
                ) {
                    throw new Error('persistent storage or CSP changed during artifact transfer');
                }
                return { success: true, workerCount: workers.length };
            },
            { mode, privateBytes },
        )
        .catch((error) => {
            throw new Error(
                JSON.stringify({ mode, responses, networkFailures, pageErrors: errors }),
                {
                    cause: error,
                },
            );
        });
    assert.equal(result.success, true);
    assert(result.workerCount >= 1);
    assert.deepEqual(errors, []);
    assert.deepEqual(
        privateRequests,
        [],
        'local evidence key/passphrase bytes must never enter HTTP',
    );
    console.log(JSON.stringify(result));
} finally {
    await browser.close();
}
