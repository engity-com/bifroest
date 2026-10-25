import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const [origin, mode] = process.argv.slice(2);
assert.match(origin, /^https:\/\/app\.example\.org:[0-9]+$/u);
assert(['normal', 'held-success', 'held-failure'].includes(mode));
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
  page.on('pageerror', (error) => errors.push(error.message));
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
  const result = await page.evaluate(
    async ({ mode }) => {
      const { BrowserClient } = await import('/_bifroest/test/client.js');
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
      const entry = await fetch('/_bifroest/test/artifact-id', { credentials: 'omit' }).then(
        (response) => response.json(),
      );
      const selected = { kind: 'recording', auditlog: 'default', id: entry.id };
      if (mode !== 'normal') {
        await fetch('/_bifroest/test/artifact-arm', { method: 'POST', credentials: 'omit' });
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
        await fetch('/_bifroest/test/artifact-release', { method: 'POST', credentials: 'omit' });
        const completed = await operation;
        if (mode === 'held-failure') {
          if (completed.error !== 'unavailable' || completed.value !== undefined) {
            throw new Error('a failed final audit released provisional artifact data');
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
        if (digest !== recording.metadata.SHA256 || recording.metadata.ID !== entry.id) {
          throw new Error('recording sink bytes or selectors differ from the completed transfer');
        }
        const audit = await access.downloadArtifact({ kind: 'audit', auditlog: 'default' });
        if (
          audit.transport !== 'complete' ||
          audit.evidence !== 'unverified' ||
          audit.metadata.Name !== 'default'
        ) {
          throw new Error('audit transport was not decoded as provisional-trust data');
        }
        if (
          !audit.files.some((file) => file.name === 'head.cbor') ||
          audit.files.length !== audit.metadata.Files.length
        ) {
          throw new Error('audit sink omitted a declared immutable file');
        }
      }
      if (
        workers.some(
          (worker) =>
            !worker.terminated || worker.requests.some((message) => message.includes('bwa1.')),
        )
      ) {
        throw new Error('an owned transport worker survived or received an authentication bearer');
      }
      if (localStorage.length !== 0 || sessionStorage.length !== 0 || violations.length !== 0) {
        throw new Error('persistent storage or CSP changed during artifact transfer');
      }
      return { success: true, workerCount: workers.length };
    },
    { mode },
  );
  assert.equal(result.success, true);
  assert(result.workerCount >= 1);
  assert.deepEqual(errors, []);
  console.log(JSON.stringify(result));
} finally {
  await browser.close();
}
