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
