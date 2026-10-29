import { describe, expect, it, vi } from 'vitest';
import { readBoundedWasmBody } from '../src/wasm/response-body';

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
