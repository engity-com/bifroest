import { afterEach, describe, expect, it, vi } from 'vitest';
import { recordingSourceMediaType, transferMediaType } from '../src/artifacts/protocol';
import { ManagementSourceTransfer } from '../src/management/source-transfer';
import { RememberMeError } from '../src/remember/protocol';

const id = '34e34ab8-7457-4d88-a5e4-c57791775c3a';
const sources: ManagementSourceTransfer[] = [];
function fixture(total = 2) {
  const stopped = new AbortController();
  const sent = vi.fn();
  const remove = vi.fn();
  const stop = vi.fn();
  const stream = new ManagementSourceTransfer('7', 'default', stopped.signal, sent, remove, stop);
  sources.push(stream);
  stream.receive({
    type: 'response',
    requestId: '7',
    status: 200,
    contentType: recordingSourceMediaType,
  });
  stream.receive({ type: 'source-start', requestId: '7', source: 'default', total });
  return { stream, stopped, sent, remove, stop };
}
function begin(stream: ManagementSourceTransfer, index: number) {
  stream.receive({
    type: 'source-entry',
    requestId: '7',
    index,
    recordingId: id,
    status: 200,
    contentType: transferMediaType,
    encrypted: false,
    recipient: '',
  });
}
afterEach(() => {
  for (const source of sources.splice(0)) {
    source.interrupt(new RememberMeError('cancelled'));
  }
  vi.useRealTimers();
});
describe('source transfer framing, not native artifact or cryptographic verification', () => {
  it('requires explicit one-file credit and does not report whole-source completion early', async () => {
    const { stream, sent, remove } = fixture();
    await stream.ready;
    expect(sent).not.toHaveBeenCalled();
    let closed = false;
    void stream.closed.then(() => {
      closed = true;
    });
    const first = stream.next();
    await Promise.resolve();
    expect(sent).toHaveBeenLastCalledWith({ type: 'source-next', requestId: '7', index: '1' });
    begin(stream, 1);
    stream.append(new Uint8Array([1, 2, 3]));
    let released = false;
    void first.then(() => {
      released = true;
    });
    await Promise.resolve();
    expect(released).toBe(false);
    stream.receive({ type: 'source-entry-complete', requestId: '7', index: 1 });
    const received = await first;
    expect(received.done).toBe(false);
    if (received.done) {
      throw new Error('missing response image');
    }
    expect([...new Uint8Array(received.value.image.bytes)]).toEqual([1, 2, 3]);
    expect('transport' in received.value).toBe(false);
    expect('evidence' in received.value).toBe(false);
    expect(closed).toBe(false);
    expect(sent).toHaveBeenCalledTimes(1);
    const second = stream.next();
    await Promise.resolve();
    expect(sent).toHaveBeenLastCalledWith({ type: 'source-next', requestId: '7', index: '2' });
    begin(stream, 2);
    stream.append(new Uint8Array([4]));
    stream.receive({ type: 'source-entry-complete', requestId: '7', index: 2 });
    await second;
    expect(closed).toBe(false);
    stream.receive({ type: 'complete', requestId: '7' });
    await stream.closed;
    expect(remove).toHaveBeenCalledOnce();
    expect((await stream.next()).done).toBe(true);
  });
  it('rejects unsolicited data, skipped indices and incomplete whole-source completion', async () => {
    const { stream } = fixture();
    await stream.ready;
    expect(() => stream.append(new Uint8Array([1]))).toThrow();
    const next = stream.next();
    void next.catch(() => {});
    await Promise.resolve();
    expect(() => begin(stream, 2)).toThrow();
    expect(() => stream.receive({ type: 'complete', requestId: '7' })).toThrow();
  });
  it('does not request any file from an empty inventory', async () => {
    const { stream, sent } = fixture(0);
    const next = stream.next();
    await Promise.resolve();
    expect(sent).not.toHaveBeenCalled();
    stream.receive({ type: 'complete', requestId: '7' });
    expect((await next).done).toBe(true);
  });
  it('cancels without releasing provisional bytes, retries, or opening another request', async () => {
    const { stream, sent, stopped } = fixture();
    const next = stream.next();
    const observed = expect(next).rejects.toMatchObject({ code: 'cancelled' });
    await Promise.resolve();
    begin(stream, 1);
    stream.append(new Uint8Array([1]));
    stopped.abort();
    await observed;
    expect(sent.mock.calls).toEqual([
      [{ type: 'source-next', requestId: '7', index: '1' }],
      [{ type: 'cancel', requestId: '7' }],
    ]);
    stream.append(new Uint8Array([2]));
    stream.receive({ type: 'canceled', requestId: '7' });
    await stream.closed;
    expect(sent).toHaveBeenCalledTimes(2);
  });
  it('preserves an actual per-file denial without accepting a later success', async () => {
    const { stream, remove } = fixture();
    const next = stream.next();
    const observed = expect(next).rejects.toMatchObject({ code: 'denied' });
    await Promise.resolve();
    stream.receive({ type: 'source-failed', requestId: '7', status: 403 });
    await observed;
    expect(remove).not.toHaveBeenCalled();
    stream.receive({ type: 'canceled', requestId: '7' });
    await stream.closed;
    await expect(stream.next()).rejects.toMatchObject({ code: 'denied' });
  });
});
