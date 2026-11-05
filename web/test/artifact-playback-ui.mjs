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
  const playback = panel.getByRole('region', { name: 'Recording playback', exact: true });
  await playback.locator('[data-playback-phase="paused"]').waitFor();
  const preparations = () =>
    page.evaluate(() =>
      window.ownedWorkers
        .filter((worker) => worker.workerName === 'bifroest-playback')
        .map((worker) => worker.requests.map((request) => JSON.parse(request))),
    );
  const prepared = await preparations();
  assert.equal(prepared.length, 1, 'opening prepares the exact verified Cast once');
  assert.deepEqual(
    prepared[0].filter((request) => request.kind === 'playback').map((request) => request.options),
    [{ id: entry.id, producer: '', allowUntrusted: true }],
    'prefilled file metadata is never promoted to an independent player pin',
  );
  assert.deepEqual(
    await page.evaluate(() =>
      Promise.all(
        window.ownedWorkers
          .filter((worker) => worker.workerName === 'bifroest-playback')
          .flatMap((worker) => worker.playbackDigests),
      ),
    ),
    [createHash('sha256').update(cast.bytes).digest('hex')],
  );
  assert.equal(
    (await playback.locator('.xterm-accessibility-tree').textContent()).includes('PLAYBACK_ONLY'),
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
  await page.keyboard.press('Escape');
  await page.waitForFunction(() => document.fullscreenElement === null);
  assert.equal((await preparations()).length, 1);
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
  await workspace(page, 'Recordings');
  await page.evaluate(
    () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
  );
  assert.equal((await preparations()).length, 1);
  assert.equal(await playback.locator('.xterm').count(), 0);
  assert.equal(apiRequests.length, before);
  await playback.getByRole('button', { name: 'Prepare player', exact: true }).click();
  await playback.locator('[data-playback-phase="paused"]').waitFor();
  assert.equal((await preparations()).length, 2);
  assert.equal(apiRequests.length, before);
}
