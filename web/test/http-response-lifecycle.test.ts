import { afterEach, describe, expect, it, vi } from 'vitest';
import { Http } from '../src/remember/http';

const scope = { origin: location.origin.replace('http:', 'https:'), slug: 'Work' };
const token = `bwa1.${'A'.repeat(43)}`;

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

function reply(bytes = new TextEncoder().encode('{"target":{"flow":"Worker","id":"fixture"}}')) {
  const reader = {
    read: vi
      .fn()
      .mockResolvedValueOnce({ done: false, value: bytes })
      .mockResolvedValueOnce({ done: true }),
    cancel: vi.fn().mockResolvedValue(undefined),
    releaseLock: vi.fn(),
  };
  const body = { getReader: () => reader, cancel: vi.fn().mockResolvedValue(undefined) };
  const response = {
    status: 202,
    redirected: false,
    type: 'default',
    headers: new Headers({ 'Content-Type': 'application/json' }),
    body,
  } as unknown as Response;
  return { reader, body, response };
}

describe('bounded JSON response lifecycle (transport fixtures, not mutation authorization)', () => {
  it('releases a consumed response without cancel after EOF or later operation retirement', async () => {
    const { reader, response } = reply();
    let transportSignal!: AbortSignal;
    const transport = vi.fn(async (_url, options) => {
      transportSignal = options.signal;
      return response;
    });
    const lifetime = new AbortController();
    const http = new Http(scope, transport);
    expect(await http.post('management/sessions/prepare', {}, token, 202, lifetime.signal)).toEqual(
      { target: { flow: 'Worker', id: 'fixture' } },
    );
    expect(reader.cancel).not.toHaveBeenCalled();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
    lifetime.abort();
    expect(transportSignal.aborted).toBe(false);
    expect(transport).toHaveBeenCalledOnce();
  });

  it('cancels an incomplete oversized response without raising the 64-KiB ceiling or retrying', async () => {
    const { reader, response } = reply(new Uint8Array((64 << 10) + 1));
    let transportSignal!: AbortSignal;
    const transport = vi.fn(async (_url, options) => {
      transportSignal = options.signal;
      return response;
    });
    await expect(
      new Http(scope, transport).post('management/sessions/prepare', {}, token, 202),
    ).rejects.toMatchObject({ code: 'unavailable' });
    expect(reader.cancel).toHaveBeenCalledOnce();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
    expect(transportSignal.aborted).toBe(true);
    expect(transport).toHaveBeenCalledOnce();
  });

  it('propagates cancellation during a pending request without returning or replaying a response', async () => {
    let transportSignal!: AbortSignal;
    const transport = vi.fn(
      (_url, options) =>
        new Promise<Response>((_resolve, reject) => {
          transportSignal = options.signal;
          transportSignal.addEventListener(
            'abort',
            () => reject(new Error('private provider detail')),
            { once: true },
          );
        }),
    );
    const controller = new AbortController();
    const result = new Http(scope, transport).post(
      'management/sessions/prepare',
      {},
      token,
      202,
      controller.signal,
    );
    const observed = expect(result).rejects.toMatchObject({ code: 'cancelled' });
    controller.abort();
    await observed;
    expect(transportSignal.aborted).toBe(true);
    expect(transport).toHaveBeenCalledOnce();
  });

  it('keeps the twenty-second deadline but does not cancel a completed response afterward', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    vi.spyOn(AbortSignal, 'timeout').mockImplementation((milliseconds) => {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), milliseconds);
      return controller.signal;
    });
    const { response } = reply();
    let completed!: AbortSignal;
    await new Http(
      scope,
      vi.fn(async (_url, options) => {
        completed = options.signal;
        return response;
      }),
    ).post('management/sessions/prepare', {}, token, 202);
    await vi.advanceTimersByTimeAsync(20_001);
    expect(completed.aborted).toBe(false);
    let pending!: AbortSignal;
    const transport = vi.fn(
      (_url, options) =>
        new Promise<Response>((_resolve, reject) => {
          pending = options.signal;
          pending.addEventListener('abort', () => reject(new Error('deadline')), { once: true });
        }),
    );
    const result = expect(
      new Http(scope, transport).post('management/sessions/prepare', {}, token, 202),
    ).rejects.toMatchObject({ code: 'unavailable' });
    await vi.advanceTimersByTimeAsync(20_001);
    await result;
    expect(pending.aborted).toBe(true);
    expect(transport).toHaveBeenCalledOnce();
  });

  it('still rejects HTTP denials and invalid JSON; only incomplete transport is cancelled', async () => {
    const denied = reply();
    Object.defineProperty(denied.response, 'status', { value: 403 });
    const deniedTransport = vi.fn(async () => denied.response);
    await expect(
      new Http(scope, deniedTransport).post('management/sessions/prepare', {}, token, 202),
    ).rejects.toMatchObject({ code: 'denied' });
    expect(denied.body.cancel).toHaveBeenCalledOnce();
    expect(deniedTransport).toHaveBeenCalledOnce();
    const malformed = reply(new TextEncoder().encode('not JSON'));
    await expect(
      new Http(
        scope,
        vi.fn(async () => malformed.response),
      ).post('management/sessions/prepare', {}, token, 202),
    ).rejects.toMatchObject({ code: 'unavailable' });
    expect(malformed.reader.cancel).not.toHaveBeenCalled();
    expect(malformed.reader.releaseLock).toHaveBeenCalledOnce();
  });
});
