import { describe, expect, it, vi } from 'vitest';
import { readBoundedWasmBody, readBoundedWasmResponse } from '../src/wasm/response-body';

function imageReader() {
  const reader = {
    read: vi.fn(),
    cancel: vi.fn().mockResolvedValue(undefined),
    releaseLock: vi.fn(),
  };
  const body = { getReader: () => reader } as unknown as ReadableStream<Uint8Array>;
  return { reader, body };
}

describe('bounded public WASM image lifecycle, not a cryptographic verifier', () => {
  it('joins a fully completed image without cancelling a request after EOF', async () => {
    const { reader, body } = imageReader();
    reader.read
      .mockResolvedValueOnce({ done: false, value: new Uint8Array([0, 97]) })
      .mockResolvedValueOnce({ done: false, value: new Uint8Array([115, 109]) })
      .mockResolvedValueOnce({ done: true });
    expect(await readBoundedWasmBody(body)).toEqual(new Uint8Array([0, 97, 115, 109]));
    expect(reader.cancel).not.toHaveBeenCalled();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
  });

  it('cancels an incomplete oversized image without raising the existing 8-MiB ceiling', async () => {
    const { reader, body } = imageReader();
    reader.read.mockResolvedValueOnce({ done: false, value: new Uint8Array((8 << 20) + 1) });
    await expect(readBoundedWasmBody(body)).rejects.toThrow('byte limit');
    expect(reader.cancel).toHaveBeenCalledOnce();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
  });

  it('releases an aborted reader even if incomplete-body cleanup itself rejects', async () => {
    const { reader, body } = imageReader();
    const failure = new Error('request aborted');
    reader.read.mockRejectedValueOnce(failure);
    reader.cancel.mockRejectedValueOnce(new Error('already aborted'));
    await expect(readBoundedWasmBody(body)).rejects.toBe(failure);
    expect(reader.cancel).toHaveBeenCalledOnce();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
  });
});

function responseReader(size = 4, nativeSize = size) {
  const { reader, body } = imageReader();
  reader.read
    .mockResolvedValueOnce({ done: false, value: new Uint8Array(size) })
    .mockResolvedValueOnce({ done: true });
  const original = { cancel: vi.fn().mockResolvedValue(undefined) };
  const response = {
    clone: vi.fn(() => ({ body })),
    body: original,
    arrayBuffer: vi.fn(async () => new ArrayBuffer(nativeSize)),
  } as unknown as Response;
  return { reader, original, response };
}

describe('bounded preflight before the original native fetch-body consumer', () => {
  it('does not invoke arrayBuffer before bounded clone EOF and retains exact length', async () => {
    const { reader, original, response } = responseReader();
    const aborted = vi.fn();
    vi.mocked(response.arrayBuffer).mockImplementation(async () => {
      expect(reader.read).toHaveBeenCalledTimes(2);
      expect(reader.releaseLock).toHaveBeenCalledOnce();
      return new ArrayBuffer(4);
    });
    expect((await readBoundedWasmResponse(response, aborted)).byteLength).toBe(4);
    expect(response.clone).toHaveBeenCalledOnce();
    expect(response.arrayBuffer).toHaveBeenCalledOnce();
    expect(reader.cancel).not.toHaveBeenCalled();
    expect(original.cancel).not.toHaveBeenCalled();
    expect(aborted).not.toHaveBeenCalled();
  });

  it('never starts an unbounded native consumer for an oversized clone and joins both cancellations', async () => {
    const { reader, original, response } = responseReader((8 << 20) + 1);
    const both = Promise.withResolvers<void>();
    const attempted = new Set<string>();
    const cancel = (branch: string) => {
      attempted.add(branch);
      if (attempted.size === 2) {
        both.resolve();
      }
      return both.promise;
    };
    reader.cancel.mockImplementation(() => cancel('checking'));
    original.cancel.mockImplementation(() => cancel('original'));
    const aborted = vi.fn();
    await expect(readBoundedWasmResponse(response, aborted)).rejects.toThrow('byte limit');
    expect(response.arrayBuffer).not.toHaveBeenCalled();
    expect([...attempted].sort()).toEqual(['checking', 'original']);
    expect(reader.cancel).toHaveBeenCalledOnce();
    expect(original.cancel).toHaveBeenCalledOnce();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
    expect(aborted).toHaveBeenCalled();
  });

  it('rejects a contradictory native image and aborts/cancels instead of accepting it', async () => {
    const { reader, original, response } = responseReader(4, 5);
    const aborted = vi.fn();
    await expect(readBoundedWasmResponse(response, aborted)).rejects.toThrow('length changed');
    expect(reader.cancel).not.toHaveBeenCalled();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
    expect(original.cancel).toHaveBeenCalledOnce();
    expect(aborted).toHaveBeenCalled();
  });

  it('cleans both branches on failed reads even when cancellation rejects', async () => {
    const { reader, original, response } = responseReader();
    const failure = new Error('read aborted');
    reader.read.mockReset().mockRejectedValue(failure);
    reader.cancel.mockRejectedValue(new Error('checking already errored'));
    original.cancel.mockRejectedValue(new Error('original already errored'));
    await expect(readBoundedWasmResponse(response, vi.fn())).rejects.toBe(failure);
    expect(response.arrayBuffer).not.toHaveBeenCalled();
    expect(reader.cancel).toHaveBeenCalledOnce();
    expect(original.cancel).toHaveBeenCalledOnce();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
  });

  it('accepts the exact eight-MiB boundary without increasing it', async () => {
    const { reader, response } = responseReader(8 << 20);
    expect((await readBoundedWasmResponse(response, vi.fn())).byteLength).toBe(8 << 20);
    expect(response.arrayBuffer).toHaveBeenCalledOnce();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
  });

  it('retains a native-consumer failure even if abort and original cancellation also fail', async () => {
    const { reader, original, response } = responseReader();
    const failure = new Error('native body failed');
    vi.mocked(response.arrayBuffer).mockRejectedValue(failure);
    original.cancel.mockRejectedValue(new Error('already errored'));
    await expect(
      readBoundedWasmResponse(response, () => {
        throw new Error('abort hook failed');
      }),
    ).rejects.toBe(failure);
    expect(original.cancel).toHaveBeenCalledOnce();
    expect(reader.cancel).not.toHaveBeenCalled();
    expect(reader.releaseLock).toHaveBeenCalledOnce();
  });

  it('aborts and cancels the original if response cloning itself fails', async () => {
    const { reader, original, response } = responseReader();
    const failure = new Error('cloning failed');
    vi.mocked(response.clone).mockImplementation(() => {
      throw failure;
    });
    const abort = vi.fn();
    await expect(readBoundedWasmResponse(response, abort)).rejects.toBe(failure);
    expect(response.arrayBuffer).not.toHaveBeenCalled();
    expect(reader.read).not.toHaveBeenCalled();
    expect(original.cancel).toHaveBeenCalledOnce();
    expect(abort).toHaveBeenCalledOnce();
  });
});
