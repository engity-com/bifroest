import { describe, expect, it, vi } from 'vitest';
import { ManagementResponseBuffer } from '../src/management/response-buffer';

describe('fragment-count independent management response ownership', () => {
  it('retains fixed slabs rather than one allocation for each one-byte WebSocket payload', () => {
    const maximum = 3 * (64 << 10) + 17;
    const allocations: Uint8Array<ArrayBuffer>[] = [];
    const buffer = new ManagementResponseBuffer(maximum, (length) => {
      const bytes = new Uint8Array(length);
      allocations.push(bytes);
      return bytes;
    });
    const single = new Uint8Array(1);
    for (let index = 0; index < maximum; index++) {
      single[0] = index % 251;
      buffer.append(single);
    }
    expect(allocations.map((bytes) => bytes.byteLength)).toEqual([
      64 << 10,
      64 << 10,
      64 << 10,
      17,
    ]);
    const assembled = buffer.assemble();
    expect(allocations).toHaveLength(5);
    expect(new Uint8Array(assembled)).toEqual(
      Uint8Array.from({ length: maximum }, (_, index) => index % 251),
    );
    expect(allocations.slice(0, -1).every((bytes) => bytes.every((value) => value === 0))).toBe(
      true,
    );
    new Uint8Array(assembled).fill(0);
  });
  it('rejects the first excess byte and wipes retained fragments on cancellation', () => {
    const block = new Uint8Array(3);
    const buffer = new ManagementResponseBuffer(3, () => block);
    buffer.append(new Uint8Array([7, 8, 9]));
    expect(() => buffer.append(new Uint8Array([10]))).toThrow();
    expect([...block]).toEqual([7, 8, 9]);
    buffer.wipe();
    expect([...block]).toEqual([0, 0, 0]);
  });
  it('wipes all retained slabs when allocating the final owned image fails', () => {
    const slab = new Uint8Array(100);
    const buffer = new ManagementResponseBuffer(100, (length) => {
      if (length === 3) {
        throw new Error('simulated allocation failure');
      }
      return slab;
    });
    buffer.append(new Uint8Array([7, 8, 9]));
    expect(() => buffer.assemble()).toThrow();
    expect(slab.every((value) => value === 0)).toBe(true);
  });
  it('also wipes a partially assembled result on a copy failure', () => {
    const allocations: Uint8Array<ArrayBuffer>[] = [];
    const buffer = new ManagementResponseBuffer(100, (length) => {
      const result = new Uint8Array(length);
      allocations.push(result);
      if (length === 3) {
        vi.spyOn(result, 'set').mockImplementation(() => {
          result.fill(99);
          throw new Error('simulated copy failure');
        });
      }
      return result;
    });
    buffer.append(new Uint8Array([7, 8, 9]));
    expect(() => buffer.assemble()).toThrow();
    expect(allocations.every((bytes) => bytes.every((value) => value === 0))).toBe(true);
  });
});
