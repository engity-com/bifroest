import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { workspace } from './workspace-ui.mjs';

// Same real-player invariants as the manual-expectations workflow: usability
// changes must not weaken byte identity, locality, read-only behavior or layout.
export async function exerciseArtifactPlayback({
    page,
    context,
    panel,
    origin,
    entry,
    apiRequests,
    terminalSockets,
    save,
}) {
    const before = apiRequests.length;
    const title = await page.title();
    const pages = context.pages().length;
    const cast = await save();
    assert.equal(cast.filename, `recording-${entry.id}.cast`);
    assert(cast.bytes.toString().includes('# bifroest:signature:v1 '));
    const metadataLine = cast.bytes
        .toString()
        .split('\n', 3)
        .find((line) => line.startsWith('# bifroest:metadata:v1 '));
    assert(metadataLine);
    const metadata = JSON.parse(metadataLine.slice('# bifroest:metadata:v1 '.length));
    assert.equal(metadata.recordingId, entry.id);
    assert.equal(
        await page.getByRole('navigation', { name: 'Breadcrumb', exact: true }).textContent(),
        `Bifröst/Audit logs/default/Recordings/${entry.id}`,
    );
    const playback = panel.getByRole('region', { name: 'Recording playback', exact: true });
    await playback.locator('[data-playback-phase="paused"]').waitFor();
    const preparations = () =>
        page.evaluate(() =>
            window.ownedWorkers
                .filter((worker) => worker.workerName === 'bifroest-recording-open')
                .map((worker) => worker.requests.map((request) => JSON.parse(request))),
        );
    const prepared = await preparations();
    const decodingCount = (values) =>
        values.flat().filter((request) => request.kind === 'open-recording').length;
    const initialPreparations = decodingCount(prepared);
    assert(
        initialPreparations >= 2,
        'the initial preview and explicitly verified replay both decode the owned recording',
    );
    for (const requests of prepared) {
        assert.equal(requests[0].kind, 'recording-init');
        assert.equal(requests[0].id, entry.id);
        for (const request of requests.filter((value) => value.kind === 'open-recording')) {
            assert.equal(request.id, entry.id);
            assert.deepEqual(Object.keys(request).sort(), [
                'data',
                'id',
                'kind',
                'passphrase',
                'privateKey',
            ]);
        }
    }
    assert.equal(
        await page.evaluate(
            () =>
                window.ownedWorkers.filter((worker) => worker.workerName === 'bifroest-playback')
                    .length,
        ),
        0,
        'playback never invokes the signature-verifying preparation RPC',
    );
    const digests = await page.evaluate(() =>
        Promise.all(
            window.ownedWorkers
                .filter((worker) => worker.workerName === 'bifroest-recording-open')
                .flatMap((worker) => worker.playbackDigests),
        ),
    );
    const transferred = await page.evaluate(() => [
        ...new Set(
            window.ownedWorkers.flatMap((worker) =>
                worker.receivedDigest ? [worker.receivedDigest] : [],
            ),
        ),
    ]);
    assert.equal(transferred.length, 1);
    assert.equal(digests.length, initialPreparations);
    assert(
        digests.every((digest) => digest === transferred[0]),
        'every decoder consumes exactly the same original immutable transfer, not an unrelated Cast',
    );
    assert.notEqual(
        createHash('sha256').update(cast.bytes).digest('hex'),
        transferred[0],
        'the explicitly exported Cast is distinct from its native source',
    );
    assert.equal(
        (await playback.locator('.xterm-accessibility-tree').textContent()).includes(
            'PLAYBACK_ONLY',
        ),
        false,
        'preparation must not auto-play',
    );
    const video = playback.getByRole('application', { name: 'Recording player', exact: true });
    const box = await video.boundingBox();
    assert(box && Math.abs(box.width - (box.height * 16) / 9) < 2);
    await video.getByRole('button', { name: 'Enter fullscreen', exact: true }).click();
    await page.waitForFunction(() =>
        document.fullscreenElement?.classList.contains('recording-video'),
    );
    const fullscreen = await page.evaluate(() => {
        const element = document.fullscreenElement;
        const box = element.getBoundingClientRect();
        return {
            width: box.width,
            height: box.height,
            viewportWidth: innerWidth,
            viewportHeight: innerHeight,
            controls: element.querySelector('.recording-controls') !== null,
            timeline: element.querySelector('input[type="range"]') !== null,
        };
    });
    assert(
        Math.abs(fullscreen.width - fullscreen.viewportWidth) < 2 &&
            Math.abs(fullscreen.height - fullscreen.viewportHeight) < 2,
    );
    assert(fullscreen.controls && fullscreen.timeline);
    const verification = video.locator('.recording-verification');
    const verificationBox = await verification.boundingBox();
    assert(
        verificationBox &&
            verificationBox.x > fullscreen.viewportWidth / 2 &&
            verificationBox.y < fullscreen.viewportHeight / 2,
    );
    await verification
        .getByRole('button', { name: 'Signature, source and export details', exact: true })
        .click();
    const details = page.getByRole('dialog', {
        name: 'Signature, source and export details',
        exact: true,
    });
    await details.waitFor();
    assert.equal(
        await details.evaluate((node) => document.fullscreenElement?.contains(node)),
        true,
    );
    await details.getByRole('button', { name: 'Close', exact: true }).click();
    await details.waitFor({ state: 'hidden' });
    await page.keyboard.press('Escape');
    await page.waitForFunction(() => document.fullscreenElement === null);
    assert.equal(decodingCount(await preparations()), initialPreparations);
    assert.equal(apiRequests.length, before);
    await playback.getByRole('button', { name: 'Play', exact: true }).click();
    await playback.locator('[data-playback-phase="ended"]').waitFor();
    assert.equal(
        await playback.getByRole('button', { name: 'Play again', exact: true }).isEnabled(),
        true,
    );
    await playback
        .getByRole('region', { name: 'Read-only recording viewport', exact: true })
        .scrollIntoViewIfNeeded();
    await page.waitForFunction(() =>
        document
            .querySelector('.playback-surface .xterm-accessibility-tree')
            ?.textContent?.includes('PLAYBACK_ONLY'),
    );
    assert.equal(await page.title(), title, 'recorded OSC cannot rename the application');
    await playback.locator('.recording-video').scrollIntoViewIfNeeded();
    const link = await playback
        .locator('.xterm-accessibility-tree')
        .getByText('blocked-playback-link', { exact: true })
        .boundingBox();
    assert(link);
    assert.equal(
        await page.evaluate(
            ({ x, y }) => Boolean(document.elementFromPoint(x, y)?.closest('.playback-surface')),
            { x: link.x + link.width / 2, y: link.y + link.height / 2 },
        ),
        true,
    );
    await page.mouse.click(link.x + link.width / 2, link.y + link.height / 2);
    assert.equal(context.pages().length, pages);
    assert.equal(new URL(page.url()).origin, origin);
    await playback.getByRole('button', { name: 'Start over', exact: true }).click();
    await playback.locator('[data-playback-phase="paused"]').waitFor();
    await page.waitForFunction(() => {
        const tree = document.querySelector('.playback-surface .xterm-accessibility-tree');
        return tree !== null && !tree.textContent.includes('PLAYBACK_ONLY');
    });
    await playback.getByRole('combobox', { name: 'Speed', exact: true }).selectOption('2');
    await playback.getByRole('button', { name: 'Play', exact: true }).click();
    await playback.locator('[data-playback-phase="ended"]').waitFor();
    await playback.getByRole('button', { name: 'Start over', exact: true }).click();
    await playback.locator('[data-playback-phase="paused"]').waitFor();
    await playback.getByRole('button', { name: 'Play', exact: true }).click();
    await playback.getByRole('button', { name: 'Pause', exact: true }).click();
    await playback.locator('[data-playback-phase="paused"]').waitFor();
    assert.equal(apiRequests.length, before, 'all playback actions stay local');
    assert.equal(terminalSockets(), 0);
    assert.equal(await page.evaluate(() => window.artifactURLs.size), 1);
    await playback.getByRole('button', { name: 'Close player', exact: true }).click();
    assert.equal(await playback.locator('.xterm').count(), 0);
    await workspace(page, 'Bifröst');
    await page.goBack();
    await playback.waitFor();
    await page.evaluate(
        () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
    );
    assert.equal(decodingCount(await preparations()), initialPreparations);
    assert.equal(await playback.locator('.xterm').count(), 0);
    assert.equal(apiRequests.length, before);
    const checksBeforeReopen = await page.evaluate(
        () =>
            window.ownedWorkers
                .flatMap((worker) => worker.requests.map((request) => JSON.parse(request)))
                .filter((request) => request.kind === 'verify').length,
    );
    await playback.getByRole('button', { name: 'Open recording', exact: true }).click();
    await panel
        .getByRole('region', { name: 'Recording playback', exact: true })
        .locator('[data-playback-phase="paused"]')
        .waitFor();
    assert.equal(decodingCount(await preparations()), initialPreparations + 1);
    assert.equal(
        await page.evaluate(
            () =>
                window.ownedWorkers
                    .flatMap((worker) => worker.requests.map((request) => JSON.parse(request)))
                    .filter((request) => request.kind === 'verify').length,
        ),
        checksBeforeReopen,
    );
    assert.equal(apiRequests.length, before);
}
