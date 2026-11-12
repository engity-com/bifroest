import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { chromium } from 'playwright';
import { exerciseArtifactPlayback } from './artifact-playback-ui.mjs';
import { managementWire } from './management-wire.mjs';
import {
    activeAccess,
    assertUiPreferences,
    captureLayout,
    confirmFullVerification,
    gridColumnFilter,
    logoutAccess,
    notification,
    reauthenticate,
    workspace,
} from './workspace-ui.mjs';

const [origin, mode, keyPath] = process.argv.slice(2);
assert.match(origin, /^https:\/\/app\.example\.org:[0-9]+$/u);
assert(
    [
        'ui-clear',
        'ui-encrypted',
        'ui-audit-clear',
        'ui-audit-encrypted',
        'ui-cancel-clear',
        'ui-cancel-encrypted',
    ].includes(mode),
);
const encrypted = mode.endsWith('-encrypted');
const scenario = mode.startsWith('ui-audit-')
    ? 'audit'
    : mode.startsWith('ui-cancel-')
      ? 'cancel'
      : 'recording';
const browser = await chromium.launch({
    headless: true,
    args: ['--host-resolver-rules=MAP app.example.org 127.0.0.1', '--no-proxy-server'],
});
try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: true });
    await context.addInitScript(() => {
        window.cspViolations = [];
        window.artifactStorageWrites = 0;
        for (const method of ['put', 'add']) {
            const original = IDBObjectStore.prototype[method];
            IDBObjectStore.prototype[method] = function (...args) {
                window.artifactStorageWrites++;
                return original.apply(this, args);
            };
        }
        window.addEventListener('securitypolicyviolation', (event) =>
            window.cspViolations.push(event.violatedDirective),
        );
        const WorkerType = window.Worker;
        window.ownedWorkers = [];
        window.Worker = class extends WorkerType {
            constructor(url, options) {
                super(url, options);
                this.terminated = false;
                this.workerName = options?.name ?? '';
                this.requests = [];
                this.playbackDigests = [];
                this.ready = false;
                this.sentVerification = false;
                this.failureCode = null;
                this.addEventListener('message', (event) => {
                    if (event.data?.kind === 'ready') {
                        this.ready = true;
                    }
                    if (
                        event.data?.kind === 'received' &&
                        typeof event.data.metadata?.SHA256 === 'string'
                    ) {
                        this.receivedDigest = event.data.metadata.SHA256;
                    }
                    if (event.data?.kind === 'failed') {
                        this.transferFailureReason = ['unavailable', 'too-large'].includes(
                            event.data.reason,
                        )
                            ? event.data.reason
                            : null;
                        this.failureCode = [
                            'input',
                            'key',
                            'verification',
                            'limit',
                            'unavailable',
                            'module-fetch',
                            'module-decode',
                            'runtime',
                            'protocol',
                            'worker',
                        ].includes(event.data.code)
                            ? event.data.code
                            : 'unknown';
                    }
                });
                window.ownedWorkers.push(this);
            }
            postMessage(value, transfer) {
                this.requests.push(JSON.stringify(value));
                if (value.kind === 'verify') {
                    this.sentVerification = true;
                }
                if (
                    (value.kind === 'playback' || value.kind === 'open-recording') &&
                    value.data instanceof Blob
                ) {
                    this.playbackDigests.push(
                        value.data
                            .arrayBuffer()
                            .then((bytes) => crypto.subtle.digest('SHA-256', bytes))
                            .then((digest) =>
                                [...new Uint8Array(digest)]
                                    .map((byte) => byte.toString(16).padStart(2, '0'))
                                    .join(''),
                            ),
                    );
                }
                return super.postMessage(value, transfer);
            }
            terminate() {
                this.terminated = true;
                return super.terminate();
            }
        };
        const create = URL.createObjectURL.bind(URL);
        const revoke = URL.revokeObjectURL.bind(URL);
        window.artifactURLs = new Set();
        URL.createObjectURL = (blob) => {
            const url = create(blob);
            window.artifactURLs.add(url);
            return url;
        };
        URL.revokeObjectURL = (url) => {
            window.artifactURLs.delete(url);
            return revoke(url);
        };
    });
    const page = await context.newPage();
    const wire = managementWire(page);
    const errors = [];
    const assetObservations = [];
    page.on('response', (response) => {
        const path = new URL(response.url()).pathname;
        if (
            path.endsWith('/browser-transfer.wasm') ||
            path.endsWith('/browser-transfer-worker.js') ||
            path.endsWith('/go-wasm-exec.js')
        ) {
            assetObservations.push({
                path,
                status: response.status(),
                type: response.headers()['content-type'] ?? '',
                encoding: response.headers()['content-encoding'] ?? '',
            });
        }
    });
    page.on('requestfailed', (request) => {
        const path = new URL(request.url()).pathname;
        if (path.startsWith('/_bifroest/files/')) {
            assetObservations.push({ path, error: request.failure()?.errorText ?? 'failed' });
        }
    });
    const apiRequests = [];
    const transfers = [];
    let terminalSocketCount = 0;
    let managementSocketCount = 0;
    let outboundBinary = 0;
    const grants = [];
    const logouts = [];
    const fingerprint = (value) =>
        createHash('sha256')
            .update(value ?? '')
            .digest('hex');
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('websocket', (socket) => {
        if (new URL(socket.url()).pathname.endsWith('/management/channel')) {
            managementSocketCount++;
            socket.on('framesent', ({ payload }) => {
                if (typeof payload !== 'string') {
                    outboundBinary++;
                    return;
                }
                const value = JSON.parse(payload);
                if (value.type === 'open') {
                    grants.push(fingerprint(`Bearer ${value.accessToken}`));
                }
            });
        } else {
            terminalSocketCount++;
        }
    });
    page.on('request', (request) => {
        const path = new URL(request.url()).pathname;
        assert.equal(new URL(request.url()).search, '');
        const body = request.postData() ?? '';
        assert(!body.includes('PRIVATE KEY') && !body.includes('fixture secret'));
        if (path.includes('/api/') && !path.endsWith('/management/channel')) {
            apiRequests.push(path);
        }
        if (path.endsWith('/logout')) {
            logouts.push(fingerprint(request.headers().authorization));
        }
    });
    wire.on('request', (request) => {
        const path = new URL(request.url()).pathname;
        const body = JSON.parse(request.postData());
        assert.equal(request.slug(), 'Work');
        assert(!JSON.stringify(body).includes('PRIVATE KEY'));
        apiRequests.push(path);
        if (path.includes('/management/artifacts/')) {
            transfers.push({ path, body, channel: request.channel() });
        }
    });
    const reply = await page.goto(`${origin}/Work`);
    assert.equal(reply.status(), 200);
    assert(!reply.headers()['content-security-policy'].includes('wasm-unsafe-eval'));
    const login = async (user) => {
        await page.getByLabel('User name', { exact: true }).fill(user);
        await page.getByLabel('Password', { exact: true }).fill('correct');
        await page.getByRole('button', { name: 'Sign in', exact: true }).click();
        await activeAccess(page, user);
        await page
            .getByRole('grid', {
                name: 'Configured flows (not public discovery links)',
                exact: true,
            })
            .waitFor();
    };
    await login('alice');
    const alicePaneID = await page.locator('[data-connection-active="true"]').getAttribute('id');
    const alicePane = page.locator(`#${alicePaneID}`);
    const aliceNode = await alicePane.elementHandle();
    const entry = await page.evaluate(() =>
        fetch('/_bifroest/test/artifact-id', { credentials: 'omit' }).then((response) =>
            response.json(),
        ),
    );
    const panel = () =>
        page
            .locator('[data-connection-active="true"]')
            .getByRole('region', { name: 'Recordings', exact: true });
    const auditPanel = () =>
        page
            .locator('[data-connection-active="true"]')
            .getByRole('region', { name: 'Audit logs', exact: true });
    const options = async (current) => {
        const decrypt = page.getByRole('dialog', { name: 'Decrypt recording', exact: true });
        if (await decrypt.isVisible()) {
            await decrypt.getByRole('button', { name: 'Close', exact: true }).click();
            await decrypt.waitFor({ state: 'hidden' });
        }
        const states = [];
        const state = async (stage) =>
            states.push({
                stage,
                ...(await page.evaluate(() => {
                    const pane = document.querySelector('[data-connection-active="true"]');
                    return {
                        views: [...pane.querySelectorAll('[data-audit-view]')].map((node) => ({
                            view: node.dataset.auditView,
                            phase: node.dataset.auditPhase,
                        })),
                        evidence: [...pane.querySelectorAll('[data-evidence-phase]')].map(
                            (node) => ({
                                phase: node.dataset.evidencePhase,
                                input: node.dataset.evidenceInput,
                            }),
                        ),
                        controls: [...pane.querySelectorAll('[data-grid-work-mode]')].map(
                            (node) => ({
                                mode: node.dataset.gridWorkMode,
                                disabled: node.disabled,
                                hidden: !!node.closest('[hidden]'),
                            }),
                        ),
                        dialogs: [...document.querySelectorAll('[role="dialog"]')]
                            .filter((node) => !node.closest('[aria-hidden="true"]'))
                            .map((node) => node.getAttribute('aria-labelledby')),
                    };
                })),
            });
        const dialog = page.getByRole('dialog', { name: 'Verification options', exact: true });
        if (await dialog.isVisible()) {
            return dialog;
        }
        const direct = current.getByRole('button', {
            name: 'Direct data from the server',
            exact: true,
        });
        const verify = current.getByRole('button', { name: 'Verify …', exact: true });
        const verdict = current.getByRole('button', {
            name: 'Signature, source and export details',
            exact: true,
        });
        await direct.or(verify).or(verdict).first().waitFor();
        await state('ready');
        if (await direct.isVisible()) {
            await direct.click();
            await state('after-direct');
        }
        if (
            (await current.locator('.recording-evidence').count()) &&
            (await current.locator('[data-verification-result]').isVisible())
        ) {
            await current
                .getByRole('button', { name: 'Signature, source and export details', exact: true })
                .click();
            await page
                .getByRole('dialog', { name: 'Signature, source and export details', exact: true })
                .getByRole('button', { name: 'Change verification settings', exact: true })
                .click();
            await dialog.waitFor();
            return dialog;
        }
        try {
            await verify.click();
        } catch (cause) {
            await state('failed-open-options');
            throw new Error(JSON.stringify({ stage: 'open-verification-options', states }), {
                cause,
            });
        }
        await dialog.waitFor();
        return dialog;
    };
    const checkAgain = async (current) => {
        const dialog = await options(current);
        await dialog.getByRole('button', { name: 'Start verification', exact: true }).click();
        await dialog.waitFor({ state: 'hidden' });
    };
    const localControls = async (current) => {
        const dialog = page.getByRole('dialog', { name: 'Verification options', exact: true });
        return (await dialog.isVisible()) ? dialog : current;
    };
    const closeOptions = async () => {
        const dialog = page.getByRole('dialog', { name: 'Verification options', exact: true });
        if (await dialog.isVisible()) {
            await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
            await dialog.waitFor({ state: 'hidden' });
        }
    };
    const select = async (current, label, value) => {
        const dialog = page.getByRole('dialog', { name: 'Verification options', exact: true });
        const owner = (await dialog.isVisible()) ? dialog : await options(current);
        await owner.getByRole('combobox', { name: label, exact: true }).click();
        await page.getByRole('option', { name: value, exact: true }).click();
    };
    const openDetails = async (current) => {
        await closeOptions();
        await current
            .getByRole('button', { name: 'Signature, source and export details', exact: true })
            .click();
        const dialog = page.getByRole('dialog', {
            name: 'Signature, source and export details',
            exact: true,
        });
        await dialog.waitFor();
        return dialog;
    };
    const closeDetails = async () => {
        await page
            .getByRole('dialog', { name: 'Signature, source and export details', exact: true })
            .getByRole('button', { name: 'Close', exact: true })
            .click();
    };
    const key = async (current, password = 'tab fixture secret') => {
        const dialog = page.getByRole('dialog', { name: 'Verification options', exact: true });
        const decrypt = page.getByRole('dialog', { name: 'Decrypt recording', exact: true });
        const owner = (await decrypt.isVisible())
            ? decrypt
            : (await dialog.isVisible())
              ? dialog
              : await options(current);
        await owner.getByLabel('Decryption key file (local only)', { exact: true }).setInputFiles({
            name: 'local-key.pem',
            mimeType: 'application/octet-stream',
            buffer: readFileSync(keyPath),
        });
        await owner
            .getByLabel('Decryption passphrase (optional, local only)', { exact: true })
            .fill(password);
    };
    const successful = async (current) => {
        await closeOptions();
        const status = current.getByRole('button', {
            name: 'Signature, source and export details',
            exact: true,
        });
        try {
            await status.waitFor();
            await page.waitForFunction(
                (node) => node.dataset.verificationResult === 'success',
                await status.elementHandle(),
            );
        } catch (cause) {
            throw new Error(
                JSON.stringify({
                    status: (await status.count()) ? await status.textContent() : 'missing',
                    headings: await page.getByRole('heading').allTextContents(),
                    errors,
                    grids: await page
                        .getByRole('grid')
                        .evaluateAll((nodes) =>
                            nodes.map((node) => node.getAttribute('aria-label')),
                        ),
                    notices: await current.getByRole('status').allTextContents(),
                    assetObservations,
                    workers: await page.evaluate(() =>
                        window.ownedWorkers.map((worker) => ({
                            name: worker.workerName,
                            ready: worker.ready,
                            sent: worker.sentVerification,
                            terminated: worker.terminated,
                            code: worker.failureCode,
                            transferFailureReason: worker.transferFailureReason ?? null,
                        })),
                    ),
                }),
                { cause },
            );
        }
    };
    const save = async (current) => {
        const dialog = await options(current);
        const downloading = page.waitForEvent('download');
        await dialog.getByRole('button', { name: 'Save verified export', exact: true }).click();
        const download = await downloading;
        const chunks = [];
        for await (const chunk of await download.createReadStream()) {
            chunks.push(chunk);
        }
        await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
        await dialog.waitFor({ state: 'hidden' });
        return { filename: download.suggestedFilename(), bytes: Buffer.concat(chunks) };
    };
    let releaseModule;
    let enteredModule;
    let cancelledModule = false;
    if (scenario === 'cancel') {
        const entered = Promise.withResolvers();
        const released = Promise.withResolvers();
        enteredModule = entered.promise;
        releaseModule = () => released.resolve();
        await context.route('**/browser-evidence.wasm.gz', async (route) => {
            entered.resolve();
            await released.promise;
            try {
                await route.continue();
            } catch (error) {
                if (!cancelledModule) {
                    throw error;
                }
            }
        });
    }
    await workspace(page, 'Recordings');
    await panel().getByRole('grid', { name: 'Recordings · default', exact: true }).waitFor();
    assert.equal(transfers.length, 0, 'metadata discovery never downloads content');
    await panel()
        .getByRole('button', { name: `Open recording ${entry.id}`, exact: true })
        .click();
    if (scenario === 'cancel') {
        await enteredModule;
        await panel()
            .getByRole('button', { name: 'Cancel artifact operation', exact: true })
            .click();
        await panel().getByText('Artifact operation cancelled.', { exact: false }).waitFor();
        assert.equal(
            await panel().locator('.recording-verification [data-verification-result]').count(),
            0,
        );
        const count = await page.evaluate(
            () =>
                window.ownedWorkers.filter(
                    (worker) => worker.workerName === 'bifroest-recording-open',
                ).length,
        );
        assert.equal(count, 1);
        assert.equal(
            await page.evaluate(
                () =>
                    window.ownedWorkers
                        .filter((worker) => worker.workerName === 'bifroest-recording-open')
                        .at(-1).terminated,
            ),
            true,
        );
        cancelledModule = true;
        releaseModule();
        await context.unroute('**/browser-evidence.wasm.gz');
        await page.evaluate(
            () =>
                new Promise((resolve) =>
                    requestAnimationFrame(() => requestAnimationFrame(resolve)),
                ),
        );
        assert.equal(
            await page.evaluate(
                () =>
                    window.ownedWorkers.filter(
                        (worker) => worker.workerName === 'bifroest-recording-open',
                    ).length,
            ),
            count,
            'cancellation cannot restart a worker automatically',
        );
        await panel().getByRole('button', { name: 'Open recording', exact: true }).click();
    }
    await page
        .locator(
            '[data-connection-active="true"] .artifact-panel[aria-label="Recordings"][data-evidence-phase="idle"][data-evidence-input="true"]',
        )
        .waitFor({ state: 'attached' });
    assert.equal(
        await panel().getByRole('combobox', { name: 'Expected encryption', exact: true }).count(),
        0,
    );
    assert.equal(
        await panel().getByLabel('Expected recipient fingerprint', { exact: false }).count(),
        0,
        'the header and local key, not manual guesses, determine protection',
    );
    if (encrypted) {
        const decrypt = page.getByRole('dialog', { name: 'Decrypt recording', exact: true });
        await decrypt.getByLabel('Decryption key file (local only)', { exact: true }).waitFor();
        assert.equal(
            await page
                .locator(
                    '[data-connection-active="true"] .artifact-panel[aria-label="Recordings"] .recording-video .xterm',
                )
                .count(),
            0,
        );
        await key(panel(), 'wrong fixture secret');
        await decrypt.getByRole('button', { name: 'Unlock and open', exact: true }).click();
        await panel()
            .getByText('The local decryption key could not be imported', { exact: false })
            .waitFor();
        assert.equal(
            await panel().locator('.recording-verification [data-verification-result]').count(),
            0,
            'a decryption failure is not a signature verdict',
        );
        await panel().getByRole('button', { name: 'Unlock and open', exact: true }).click();
        await decrypt.waitFor();
        await key(panel());
        await decrypt.getByRole('button', { name: 'Unlock and open', exact: true }).click();
    }
    await panel()
        .getByRole('region', { name: 'Recording playback', exact: true })
        .locator('[data-playback-phase="paused"]')
        .waitFor();
    assert.equal(
        await panel().locator('.recording-verification [data-verification-result]').count(),
        0,
    );
    assert.equal(
        await page.evaluate(
            () =>
                window.ownedWorkers
                    .flatMap((worker) => worker.requests.map((request) => JSON.parse(request)))
                    .filter((request) => request.kind === 'verify').length,
        ),
        0,
        'opening/decrypting never starts even a header signature check',
    );
    const initialOptions = await options(panel());
    assert.equal(
        await initialOptions.getByLabel('Trusted signing ID', { exact: false }).inputValue(),
        entry.producer,
    );
    assert.equal(
        await initialOptions
            .getByRole('checkbox', {
                name: 'Check the signing identity against this ID',
                exact: true,
            })
            .isChecked(),
        true,
    );
    if (encrypted) {
        await select(
            panel(),
            'Verification depth',
            'Outer signatures/container only — no private verification',
        );
        await checkAgain(panel());
        await successful(panel());
        const outer = await openDetails(panel());
        await outer.getByText('outer', { exact: true }).waitFor();
        await closeDetails();
        await select(
            panel(),
            'Verification depth',
            'Full private semantics (decrypt when encrypted)',
        );
        await key(panel(), 'wrong fixture secret');
        await checkAgain(panel());
        await panel().locator('[data-verification-result="failure"]').waitFor();
        const failedKey = await openDetails(panel());
        await failedKey
            .getByText('The local decryption key could not be imported', { exact: false })
            .waitFor();
        await closeDetails();
        await options(panel());
        await key(panel(), 'wrong fixture secret');
        assert.equal(
            await (await localControls(panel()))
                .getByLabel('Decryption key file (local only)', { exact: true })
                .evaluate((input) => input.files.length),
            1,
            'the newly selected candidate takes precedence over the older cached key until submission',
        );
        await key(panel(), 'tab fixture secret');
        await checkAgain(panel());
    } else {
        await checkAgain(panel());
    }
    await successful(panel());
    await captureLayout(page, `artifact-${mode}-opened`);
    const originalCalls = transfers.length;
    assert.equal(originalCalls, 1);
    await options(panel());
    assert.equal(
        await (await localControls(panel()))
            .getByLabel('Trusted signing ID', { exact: false })
            .inputValue(),
        entry.producer,
    );
    assert.equal(
        await (await localControls(panel()))
            .getByLabel('Trusted signing ID', { exact: false })
            .isDisabled(),
        false,
    );
    await closeOptions();
    if (scenario === 'recording') {
        await exerciseArtifactPlayback({
            page,
            context,
            panel: panel(),
            origin,
            entry,
            apiRequests,
            terminalSockets: () => terminalSocketCount,
            save: () => save(panel()),
        });
        const trustOptions = await options(panel());
        await trustOptions
            .getByRole('checkbox', {
                name: 'Check the signing identity against this ID',
                exact: true,
            })
            .check();
        await trustOptions.getByLabel('Trusted signing ID', { exact: false }).fill('1'.repeat(64));
        const before = transfers.length;
        await checkAgain(panel());
        await panel().locator('[data-verification-result="failure"]').waitFor();
        assert.equal(
            await panel().getByRole('region', { name: 'Recording playback', exact: true }).count(),
            0,
        );
        const failed = await openDetails(panel());
        await failed.getByText('verification', { exact: true }).waitFor();
        await failed.getByText('1'.repeat(64), { exact: true }).waitFor();
        await closeDetails();
        const correctedOptions = await options(panel());
        await correctedOptions
            .getByLabel('Trusted signing ID', { exact: false })
            .fill(entry.producer);
        await checkAgain(panel());
        await successful(panel());
        assert.equal(
            transfers.length,
            before,
            'changing independent expectations must never fetch another artifact',
        );
        const pinned = await openDetails(panel());
        await pinned
            .getByText('Signature matches the user-selected signing ID', { exact: true })
            .waitFor();
        await closeDetails();
        await save(panel());
    }
    if (scenario !== 'recording') {
        await workspace(page, 'Audit logs');
        await auditPanel()
            .getByRole('grid', { name: 'Configured auditlogs (server metadata)', exact: true })
            .waitFor();
        const before = transfers.length;
        await auditPanel()
            .getByRole('button', { name: 'Open audit log default', exact: true })
            .click();
        await auditPanel()
            .getByRole('region', { name: 'Audit overview (server-reported)', exact: true })
            .getByRole('grid', { name: 'Audit events', exact: true })
            .locator('[role="row"][data-id]')
            .first()
            .waitFor();
        assert.equal(
            transfers.length,
            before,
            'audit browsing must not download or verify the full journal',
        );
        await confirmFullVerification(page, auditPanel(), 'default');
        await successful(auditPanel());
        assert.equal(transfers.length, before + 1);
        assert.equal(
            await auditPanel()
                .getByLabel('Decryption key file (local only)', { exact: true })
                .count(),
            0,
            'the successfully verified Recording key must be reused in the same tab',
        );
        const events = auditPanel().getByRole('grid', { name: 'Audit events', exact: true });
        await events.locator('[role="row"][data-id]').first().waitFor();
        await captureLayout(page, `artifact-${mode}-events`);
        const firstName = await events
            .locator('[role="row"][data-id]')
            .first()
            .locator('[data-field="name"]')
            .textContent();
        assert.match(firstName, /^[a-z-]+\.[a-z.]+$/u);
        assert.equal(
            await auditPanel()
                .getByRole('button', { name: /^Save unverified original/u })
                .count(),
            0,
            'raw files are not the primary audit view',
        );
        await events
            .locator('[role="row"][data-id]')
            .first()
            .getByRole('button', { name: /^Audit event details /u })
            .click();
        const eventDetails = page.getByRole('region', { name: 'Audit event details', exact: true });
        await eventDetails.waitFor();
        await captureLayout(page, `artifact-${mode}-event-detail`);
        assert.equal(
            await page.getByRole('dialog', { name: 'Audit event details', exact: true }).count(),
            0,
        );
        assert.equal(
            await eventDetails.getByRole('button', { name: 'Close', exact: true }).count(),
            0,
        );
        await page
            .getByRole('navigation', { name: 'Breadcrumb', exact: true })
            .getByRole('link', { name: 'default', exact: true })
            .click();
        await events.waitFor();
        const beforeLocal = apiRequests.length;
        const controls = events.locator('xpath=ancestor::div[@class="admin-data-grid"][1]');
        const eye = controls.getByRole('button', { name: /^(Show|Hide) sensitive data/u });
        assert.equal(await eye.getAttribute('aria-pressed'), 'false');
        const presentationBefore = await page.evaluate(() =>
            localStorage.getItem('bifroest-ui-v1:details'),
        );
        const gridNode = await events.elementHandle();
        await eye.click();
        try {
            await events.locator('[role="columnheader"][data-field="reason"]').waitFor();
        } catch (cause) {
            const projection = await page.evaluate(() => ({
                views: [
                    ...document.querySelectorAll(
                        '[data-connection-active="true"] [data-audit-view]',
                    ),
                ].map((node) => ({ view: node.dataset.auditView, phase: node.dataset.auditPhase })),
                evidence: [
                    ...document.querySelectorAll(
                        '[data-connection-active="true"] [data-evidence-phase]',
                    ),
                ].map((node) => ({
                    phase: node.dataset.evidencePhase,
                    received: node.dataset.evidenceInput,
                })),
                grids: [
                    ...document.querySelectorAll('[data-connection-active="true"] [role="grid"]'),
                ].map((node) => ({
                    visible: node.checkVisibility({ visibilityProperty: true }),
                    columns: [...node.querySelectorAll('[role="columnheader"]')].map(
                        (header) => header.dataset.field,
                    ),
                })),
                eyes: [
                    ...document.querySelectorAll(
                        '[data-connection-active="true"] button[aria-pressed]',
                    ),
                ].map((node) => ({
                    pressed: node.getAttribute('aria-pressed'),
                    disabled: node.disabled,
                })),
                verification: window.ownedWorkers.flatMap((worker) =>
                    worker.requests.flatMap((raw) => {
                        const request = JSON.parse(raw);
                        return request.kind === 'verify'
                            ? [
                                  {
                                      sensitive: request.options?.sensitive === true,
                                      terminated: worker.terminated,
                                  },
                              ]
                            : [];
                    }),
                ),
            }));
            throw new Error(
                JSON.stringify({
                    stage: 'local-sensitive-projection',
                    projection,
                    requestsBefore: beforeLocal,
                    requestsAfter: apiRequests.length,
                }),
                { cause },
            );
        }
        assert.equal(await eye.getAttribute('aria-pressed'), 'true');
        assert.equal(
            apiRequests.length,
            beforeLocal,
            'explicit private export reprojection is local, not another transfer or server query',
        );
        await eye.click();
        await events
            .locator('[role="columnheader"][data-field="reason"]')
            .waitFor({ state: 'hidden' });
        await controls
            .getByRole('button', { name: 'Refresh audit events', exact: true })
            .waitFor({ state: 'visible' });
        assert.equal(await events.locator('[role="columnheader"][data-field="reason"]').count(), 0);
        assert.equal(await eye.getAttribute('aria-pressed'), 'false');
        assert.equal(await gridNode.evaluate((node) => node.isConnected), true);
        assert.equal(
            apiRequests.length,
            beforeLocal,
            'the eye rebuilds verified local audit rows without refetching content',
        );
        assert.equal(
            await page.evaluate(() => localStorage.getItem('bifroest-ui-v1:details')),
            presentationBefore,
            'private-field opt-in is never an origin-wide persisted display preference',
        );
        await gridColumnFilter(page, events, 'Event', 'contains', 'session');
        await page.waitForFunction(() => {
            const rows = [
                ...document.querySelectorAll(
                    '[data-connection-active="true"] [aria-label="Audit events"] [role="row"][data-id] [data-field="name"]',
                ),
            ];
            return rows.length > 0 && rows.every((row) => row.textContent.includes('session'));
        });
        assert.equal(
            apiRequests.length,
            beforeLocal,
            'audit event filtering is local to already verified bytes',
        );
        const auditExport = await save(auditPanel());
        assert.equal(auditExport.filename, 'audit-default.jsonl');
        const records = auditExport.bytes
            .toString()
            .trim()
            .split('\n')
            .filter(Boolean)
            .map((line) => JSON.parse(line));
        assert(
            records.length > 0 && records.every((record) => typeof record.event?.name === 'string'),
        );
    }
    if (scenario === 'cancel') {
        const ownedURLs = await page.evaluate(() => window.artifactURLs.size);
        assert(ownedURLs > 0);
        await reauthenticate(page);
        await login('bob');
        const bobPane = page.locator('[data-connection-active="true"]');
        assert.notEqual(await bobPane.getAttribute('id'), alicePaneID);
        if (encrypted) {
            await workspace(page, 'Recordings');
            const bobGrid = panel().getByRole('grid', {
                name: 'Recordings · default',
                exact: true,
            });
            await bobGrid.waitFor();
            await gridColumnFilter(page, bobGrid, 'Recording ID', 'equals', entry.id);
            await panel()
                .getByRole('button', { name: `Open recording ${entry.id}`, exact: true })
                .click();
            await page
                .locator(
                    '[data-connection-active="true"] .artifact-panel[aria-label="Recordings"][data-evidence-phase="idle"][data-evidence-input="true"]',
                )
                .waitFor({ state: 'attached' });
            const decrypt = page.getByRole('dialog', { name: 'Decrypt recording', exact: true });
            await decrypt.getByLabel('Decryption key file (local only)', { exact: true }).waitFor();
            await decrypt.getByRole('button', { name: 'Close', exact: true }).click();
            await decrypt.waitFor({ state: 'hidden' });
            assert.equal(
                await panel()
                    .getByRole('region', { name: 'Recording playback', exact: true })
                    .count(),
                0,
                'a second actor must not borrow the first tab key',
            );
        }
        await workspace(page, 'Audit logs');
        await auditPanel()
            .getByRole('button', { name: 'Open audit log default', exact: true })
            .waitFor();
        await auditPanel()
            .getByRole('button', { name: 'Open audit log default', exact: true })
            .click();
        await auditPanel()
            .getByRole('region', { name: 'Audit overview (server-reported)', exact: true })
            .getByRole('grid', { name: 'Audit events', exact: true })
            .locator('[role="row"][data-id]')
            .first()
            .waitFor();
        await page.evaluate(() =>
            fetch('/_bifroest/test/artifact-arm', { method: 'POST', credentials: 'omit' }),
        );
        await confirmFullVerification(page, auditPanel(), 'default');
        await page.evaluate(() =>
            fetch('/_bifroest/test/artifact-entered', { credentials: 'omit' }),
        );
        assert.equal(
            await auditPanel()
                .getByRole('region', { name: 'Local audit verification', exact: true })
                .getByRole('grid', { name: 'Audit events', exact: true })
                .count(),
            0,
            'provisional audited transfer cannot publish event content',
        );
        const bobReply = page.waitForResponse((response) => response.url().endsWith('/logout'));
        await logoutAccess(page);
        await page.evaluate(() =>
            fetch('/_bifroest/test/artifact-release', { method: 'POST', credentials: 'omit' }),
        );
        const logout = await bobReply;
        assert.equal(logout.status(), 204);
        assert.equal(fingerprint(logout.request().headers().authorization) === grants[1], true);
        await notification(page, 'Logout confirmed.');
        await activeAccess(page, 'alice');
        assert.equal(await aliceNode.evaluate((node) => node.isConnected), true);
        assert.equal(await page.evaluate(() => window.artifactURLs.size), ownedURLs);
        assert.equal(logouts.length, 1);
    }
    assert.equal(terminalSocketCount, 0);
    assert.equal(outboundBinary, 0);
    assert.equal(managementSocketCount, scenario === 'cancel' ? 2 : 1);
    assert.equal(
        apiRequests.filter((path) => path.endsWith('/login/password')).length,
        scenario === 'cancel' ? 2 : 1,
    );
    assert.equal(apiRequests.filter((path) => path.includes('/remember/')).length, 0);
    assert.equal(await page.evaluate(() => window.artifactStorageWrites), 0);
    assert(
        transfers.every((request) =>
            [
                '/api/v1/management/artifacts/recording',
                '/api/v1/management/artifacts/audit',
            ].includes(request.path),
        ),
    );
    assert.deepEqual(transfers[0].body, { auditlog: 'default', id: entry.id });
    assert.equal(
        transfers.filter(
            (request) =>
                request.path.endsWith('/recording') && request.channel === transfers[0].channel,
        ).length,
        1,
        'Alice opens one Recording; local verification and playback never replay it',
    );
    const aliceReply = page.waitForResponse((response) => response.url().endsWith('/logout'));
    await logoutAccess(page);
    const logout = await aliceReply;
    assert.equal(logout.status(), 204);
    assert.equal(fingerprint(logout.request().headers().authorization) === grants[0], true);
    await alicePane.waitFor({ state: 'detached' });
    assert.equal(await page.getByRole('tab').count(), 0);
    assert.equal(await page.evaluate(() => window.artifactURLs.size), 0);
    assert.equal(
        await page.evaluate(() => window.ownedWorkers.every((worker) => worker.terminated)),
        true,
    );
    assert.deepEqual(errors, []);
    assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
    await assertUiPreferences(page);
    console.log(JSON.stringify({ success: true }));
} finally {
    await browser.close();
}
