import { readBoundedWasmBody } from '../wasm/response-body';

// The tab owns the public download, not the short-lived secret-key worker.
// Retiring that worker after signing must not tear down a fetch owned by its
// realm. These are transport checks, not a signature or producer-trust proof;
// key parsing and challenge verification still execute in the worker's Go core.
export async function loadLoginWasm(signal: AbortSignal): Promise<ArrayBuffer> {
  const stopped = AbortSignal.any([signal, AbortSignal.timeout(20_000)]);
  const download = new AbortController();
  const abort = () => download.abort();
  stopped.addEventListener('abort', abort, { once: true });
  try {
    if (stopped.aborted) {
      throw new Error('WASM download cancelled');
    }
    const response = await fetch('/_bifroest/files/browser-key.wasm', {
      credentials: 'omit',
      mode: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      signal: download.signal,
    });
    if (
      response.status !== 200 ||
      response.redirected ||
      !/^application\/wasm(?:;|$)/iu.test(response.headers.get('Content-Type') ?? '') ||
      response.body === null
    ) {
      throw new Error('Invalid WASM response');
    }
    const bytes = await readBoundedWasmBody(response.body);
    if (stopped.aborted) {
      throw new Error('WASM download cancelled');
    }
    return bytes.buffer;
  } catch (error) {
    download.abort();
    throw error;
  } finally {
    // Once EOF has been consumed, subsequent key retirement or the loading
    // timeout must not abort an already completed public request.
    stopped.removeEventListener('abort', abort);
  }
}
