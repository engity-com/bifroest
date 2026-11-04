// Register before the triggering action and read as soon as headers arrive,
// not after unrelated UI awaits. Header/body/completion share Playwright's
// existing default 30-second budget; this observes, never retries a request.
export function captureJsonResponse(page, pathname) {
  let timer;
  const deadline = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ error: 'response-capture-timeout' }), 30_000);
  });
  const captured = (async () => {
    try {
      const response = await page.waitForResponse(
        (response) =>
          new URL(response.url()).pathname === pathname && response.request().method() === 'POST',
        { timeout: 30_000 },
      );
      const [body, finished] = await Promise.allSettled([
        Promise.resolve().then(() => response.json()),
        Promise.resolve().then(() => response.finished()),
      ]);
      if (
        body.status !== 'fulfilled' ||
        finished.status !== 'fulfilled' ||
        finished.value !== null
      ) {
        return { error: 'response-capture-incomplete' };
      }
      return { status: response.status(), body: body.value };
    } catch {
      // Always settle to an explicit failure, even before the caller awaits.
      // Never retain a transport exception, cause or partial/private body.
      return { error: 'response-capture-failed' };
    }
  })();
  return Promise.race([captured, deadline]).finally(() => clearTimeout(timer));
}

// Test-only init script: install BEFORE BrowserClient binds its transport.
// Keep Chrome's actual fetch/DNS/TLS/Origin/abort policy, not a Node HTTP proxy.
// Do not close over module state: Playwright serializes this function.
export function installPreparationObserver() {
  const endpoint = new URL('/_bifroest/api/v1/management/sessions/prepare', location.origin).href;
  const transport = globalThis.fetch.bind(globalThis);
  globalThis.testPreparationReceipt = undefined;
  globalThis.fetch = async (...args) => {
    const response = await transport(...args);
    if (
      response.url === endpoint &&
      response.status === 202 &&
      globalThis.testPreparationReceipt === undefined
    ) {
      // Reserve exactly the first receipt, even if a second request overlaps.
      globalThis.testPreparationReceipt = { status: 202, error: 'capture-pending' };
      try {
        const { target } = await response.clone().json();
        if (
          target !== null &&
          typeof target === 'object' &&
          !Array.isArray(target) &&
          Object.keys(target).sort().join(',') === 'flow,id' &&
          typeof target.flow === 'string' &&
          target.flow.length > 0 &&
          target.flow.length <= 255 &&
          target.flow.isWellFormed() &&
          !/[\p{Cc}]/u.test(target.flow) &&
          typeof target.id === 'string' &&
          /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u.test(target.id)
        ) {
          globalThis.testPreparationReceipt = {
            status: 202,
            target: { flow: target.flow, id: target.id },
          };
        } else {
          globalThis.testPreparationReceipt = { status: 202, error: 'invalid-target' };
        }
      } catch {
        // A capture failure remains an explicit failed test observation, never
        // a raw exception/cause/body or a fabricated successful preparation.
        globalThis.testPreparationReceipt = { status: 202, error: 'capture-failed' };
      }
    }
    return response; // Original response; no new request, retry or modified body.
  };
}

import assert from 'node:assert/strict';

export function assertCatalogRequestPrivacy(request) {
  // Keep actual/expected and nested error causes boolean-only. A failed
  // privacy assertion must not become a second disclosure in CI diagnostics.
  assert.equal(new URL(request.url()).search === '', true);
  assert.equal(request.headers().cookie === undefined, true);
}
