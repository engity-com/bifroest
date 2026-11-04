import { EventEmitter } from 'node:events';

const observers = new WeakMap();

// Observe actual Playwright WebSocket frames, without replacing fetch, socket
// factories, TLS/Origin checks, request payloads or application callbacks. URLs
// below identify logical RPC operations, NOT additional HTTP requests. A wire
// request has no HTTP authorization/cookie headers: actor binding is its admitted
// channel UUID, and scope comes only from that channel's original open frame.
export function managementWire(page) {
  if (observers.has(page)) {
    return observers.get(page);
  }
  const events = new EventEmitter();
  const wire = {
    on: (name, listener) => events.on(name, listener),
    off: (name, listener) => events.off(name, listener),
    waitForResponse(predicate) {
      const pending = new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          events.off('response', received);
          reject(new Error('management-response-timeout'));
        }, 30000);
        const received = (response) => {
          if (predicate(response)) {
            clearTimeout(timeout);
            events.off('response', received);
            resolve(response);
          }
        };
        events.on('response', received);
      });
      void pending.catch(() => {});
      return pending;
    },
  };
  observers.set(page, wire);
  page.on('websocket', (socket) => {
    const endpoint = new URL(socket.url());
    if (endpoint.pathname !== '/_bifroest/api/v1/management/channel') {
      return;
    }
    endpoint.protocol = 'https:';
    let slug = '';
    let channel = '';
    const pending = new Map();
    socket.on('framesent', ({ payload }) => {
      if (typeof payload !== 'string') {
        return;
      }
      const value = JSON.parse(payload);
      if (value.type === 'open') {
        slug = value.slug;
        return;
      }
      if (value.type !== 'request') {
        return;
      }
      const url = new URL(`/_bifroest/api/v1/${value.action}`, endpoint.origin).href;
      const request = {
        url: () => url,
        method: () => 'RPC',
        headers: () => ({}),
        postData: () => JSON.stringify(value.fields),
        channel: () => channel,
        slug: () => slug,
        transport: 'websocket',
      };
      let resolve;
      let reject;
      const body = new Promise((done, fail) => {
        resolve = done;
        reject = fail;
      });
      void body.catch(() => {});
      const timer = setTimeout(() => {
        pending.delete(value.requestId);
        reject(new Error('management-body-timeout'));
      }, 30000);
      pending.set(value.requestId, {
        request,
        resolve,
        reject,
        body,
        timer,
        chunks: [],
        length: 0,
        artifact: value.action.startsWith('management/artifacts/'),
      });
      events.emit('request', request);
    });
    socket.on('framereceived', ({ payload }) => {
      if (typeof payload !== 'string') {
        if (payload.length < 8) {
          return;
        }
        const entry = pending.get(payload.readBigUInt64BE(0).toString());
        if (!entry || entry.artifact) {
          return;
        }
        entry.length += payload.length - 8;
        if (entry.length > 64 << 10) {
          entry.reject(new Error('management-body-limit'));
          entry.chunks = [];
          return;
        }
        entry.chunks.push(Buffer.from(payload.subarray(8)));
        return;
      }
      const value = JSON.parse(payload);
      if (value.type === 'ready') {
        channel = value.connectionId;
        return;
      }
      const entry = pending.get(value.requestId);
      if (!entry) {
        return;
      }
      if (value.type === 'response') {
        const response = {
          contentType: () => value.contentType,
          url: entry.request.url,
          status: () => value.status,
          request: () => entry.request,
          transport: 'websocket',
          json: async () => JSON.parse((await entry.body).toString('utf8')),
          finished: async () => {
            await entry.body;
            return null;
          },
        };
        events.emit('response', response);
      } else if (value.type === 'complete' || value.type === 'canceled') {
        clearTimeout(entry.timer);
        pending.delete(value.requestId);
        if (value.type === 'canceled') {
          entry.reject(new Error('management-response-cancelled'));
        } else {
          entry.resolve(Buffer.concat(entry.chunks));
        }
      }
    });
    socket.on('close', () => {
      for (const entry of pending.values()) {
        clearTimeout(entry.timer);
        entry.reject(new Error('management-channel-closed'));
      }
      pending.clear();
    });
  });
  return wire;
}

export function existingManagementWire(page) {
  return observers.get(page);
}
