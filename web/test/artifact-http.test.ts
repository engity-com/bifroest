import { describe, expect, it, vi } from 'vitest';
import type { ArtifactRequest } from '../src/artifacts/protocol';
import { maximumTransferImageBytes, transferMediaType } from '../src/artifacts/protocol';
import { Http, type Transport } from '../src/remember/http';

const scope = { origin: 'https://app.example.org:8443', slug: 'Work' };
const token = `bwa1.${'A'.repeat(43)}`;
const request: ArtifactRequest = {
  kind: 'recording',
  auditlog: 'default',
  id: '34e34ab8-7457-4d88-a5e4-c57791775c3a',
};
const url = `${scope.origin}/_bifroest/api/v1/management/artifacts/recording`;

function response(
  body: BodyInit | ReadableStream<Uint8Array> | null = new Uint8Array([1, 2, 3]),
  headers: Record<string, string> = { 'Content-Type': transferMediaType },
) {
  const value = new Response(body, { status: 200, headers });
  Object.defineProperty(value, 'url', { value: url, configurable: true });
  return value;
}

describe('owned artifact fetch image (not transfer/evidence verification)', () => {
  it('opens one exact scoped POST without cookies, redirects, query or credentials in its body', async () => {
    const transport = vi.fn<Transport>(async () => response());
    const http = new Http(scope, transport);
    const result = await http.artifactImage(request, token, new AbortController().signal);
    expect([...new Uint8Array(result.bytes)]).toEqual([1, 2, 3]);
    expect(result).toMatchObject({ mediaType: transferMediaType, status: 200 });
    expect(transport).toHaveBeenCalledTimes(1);
    const [target, init] = transport.mock.calls[0] ?? [];
    expect(String(target)).toBe(url);
    expect(init).toMatchObject({
      method: 'POST',
      credentials: 'omit',
      cache: 'no-store',
      mode: 'same-origin',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      headers: { Authorization: `Bearer ${token}`, Accept: transferMediaType },
    });
    expect(JSON.parse(String(init?.body))).toEqual({
      auditlog: request.auditlog,
      id: request.id,
      slug: scope.slug,
    });
    expect(String(init?.body)).not.toContain(token);
  });

  it('keeps data provisional until actual HTTP EOF and joins a pending read on cancellation', async () => {
    let entered: (() => void) | undefined;
    const reading = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let cancelled = 0;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2, 3]));
      },
      pull() {
        entered?.();
      },
      cancel() {
        cancelled++;
      },
    });
    const http = new Http(scope, async () => response(stream));
    const controller = new AbortController();
    let done = false;
    const operation = http.artifactImage(request, token, controller.signal).finally(() => {
      done = true;
    });
    const rejected = expect(operation).rejects.toMatchObject({ code: 'cancelled' });
    await reading;
    expect(done).toBe(false);
    controller.abort();
    await rejected;
    expect(cancelled).toBe(1);
    expect(stream.locked).toBe(false);
  });

  it('refuses altered authority/media/encoding/redirect assertions without retry', async () => {
    for (const change of ['foreign', 'media', 'encoding', 'redirect'] as const) {
      const value = response();
      if (change === 'foreign') {
        Object.defineProperty(value, 'url', { value: url.replace('8443', '9443') });
      }
      if (change === 'media') {
        value.headers.set('Content-Type', `${transferMediaType}; charset=utf-8`);
      }
      if (change === 'encoding') {
        value.headers.set('Content-Encoding', 'gzip');
      }
      if (change === 'redirect') {
        Object.defineProperty(value, 'redirected', { value: true });
      }
      const transport = vi.fn(async () => value);
      await expect(
        new Http(scope, transport).artifactImage(request, token, new AbortController().signal),
      ).rejects.toMatchObject({ code: 'unavailable' });
      expect(transport).toHaveBeenCalledTimes(1);
      expect(value.bodyUsed).toBe(true);
    }
  });

  it('rejects oversized and inconsistent length before releasing a response image', async () => {
    for (const length of [String(maximumTransferImageBytes + 1), '4', '-1']) {
      const value = response(new Uint8Array([1, 2, 3]), {
        'Content-Type': transferMediaType,
        'Content-Length': length,
      });
      await expect(
        new Http(scope, async () => value).artifactImage(
          request,
          token,
          new AbortController().signal,
        ),
      ).rejects.toMatchObject({
        code:
          length === String(maximumTransferImageBytes + 1) ? 'artifact-too-large' : 'unavailable',
      });
    }
  });

  it('does not turn cleanup failure into success and still releases the reader lock', async () => {
    const value = response();
    let released = 0;
    let closed = 0;
    Object.defineProperty(value.body, 'getReader', {
      value: () => ({
        read: async () => ({ done: true, value: undefined }),
        cancel: async () => {
          closed++;
          throw new Error('private cancellation detail');
        },
        releaseLock: () => {
          released++;
        },
      }),
    });
    await expect(
      new Http(scope, async () => value).artifactImage(
        request,
        token,
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ code: 'unavailable' });
    expect(closed).toBe(1);
    expect(released).toBe(1);
  });

  it('rejects untrusted selectors, cancelled starts and malformed bearer before any fetch', async () => {
    const transport = vi.fn(async () => response());
    const http = new Http(scope, transport);
    for (const selected of [
      { ...request, path: '/private' },
      { ...request, auditlog: '..' },
      { ...request, id: '00000000-0000-0000-0000-000000000000' },
      { kind: 'command', auditlog: 'default' },
    ]) {
      await expect(
        http.artifactImage(selected as ArtifactRequest, token, new AbortController().signal),
      ).rejects.toMatchObject({ code: 'unavailable' });
    }
    await expect(
      http.artifactImage(request, 'not-a-bearer', new AbortController().signal),
    ).rejects.toMatchObject({ code: 'unavailable' });
    const controller = new AbortController();
    controller.abort();
    await expect(http.artifactImage(request, token, controller.signal)).rejects.toMatchObject({
      code: 'cancelled',
    });
    expect(transport).not.toHaveBeenCalled();
  });
});
