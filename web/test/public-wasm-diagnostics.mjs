import { performance } from 'node:perf_hooks';

// Test-only observations, not interception or a signature/trust verifier. Never
// retain arbitrary request/response objects, headers, bodies or query values.
export async function observePublicKeyWasm(page, origin, stage) {
  const session = await page.context().newCDPSession(page);
  const { frameTree } = await session.send('Page.getFrameTree');
  const events = [];
  const requests = new Map();
  const started = performance.now();
  const record = (request, type, fields = {}) => {
    if (events.length < 128) {
      events.push({
        request: request.number,
        type,
        stage: stage(),
        observedMs: Math.round(performance.now() - started),
        ...fields,
      });
    }
  };
  session.on('Network.requestWillBeSent', (event) => {
    let url;
    try {
      url = new URL(event.request.url);
    } catch {
      return;
    }
    if (
      url.origin !== origin ||
      url.pathname !== '/_bifroest/files/browser-key.wasm' ||
      event.request.method !== 'GET' ||
      requests.size >= 16
    ) {
      return;
    }
    const request = { number: requests.size + 1, bytes: 0 };
    requests.set(event.requestId, request);
    record(request, 'started', {
      owner: event.frameId === frameTree.frame.id ? 'tab' : 'other',
      resourceType: event.type,
      initiator: event.initiator?.type,
      hasQuery: url.search !== '',
    });
  });
  session.on('Network.responseReceived', (event) => {
    const request = requests.get(event.requestId);
    if (request) {
      record(request, 'response', {
        status: event.response.status,
        protocol: event.response.protocol,
        mimeType: event.response.mimeType,
      });
    }
  });
  session.on('Network.dataReceived', (event) => {
    const request = requests.get(event.requestId);
    if (request && Number.isSafeInteger(event.dataLength) && event.dataLength >= 0) {
      request.bytes += event.dataLength;
    }
  });
  session.on('Network.loadingFinished', (event) => {
    const request = requests.get(event.requestId);
    if (request) {
      record(request, 'finished', {
        decodedBytes: request.bytes,
        encodedBytes: event.encodedDataLength,
      });
    }
  });
  session.on('Network.loadingFailed', (event) => {
    const request = requests.get(event.requestId);
    if (request) {
      record(request, 'failed', {
        decodedBytes: request.bytes,
        cancelled: event.canceled === true,
        error: /^net::ERR_[A-Z_0-9]+$/u.test(event.errorText) ? event.errorText : 'network-error',
      });
    }
  });
  await session.send('Network.enable');
  return { events, startedAt: Math.round(started), close: () => session.detach() };
}
