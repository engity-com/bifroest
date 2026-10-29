// A bounded public WASM image is still only transport input, not a signature or
// producer-trust proof. The caller retains status/type/origin checks and the Go
// runtime owns key import and challenge verification.
export async function readBoundedWasmBody(
  body: ReadableStream<Uint8Array>,
): Promise<Uint8Array<ArrayBuffer>> {
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let completed = false;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) {
        completed = true;
        break;
      }
      size += part.value.length;
      if (size > 8 << 20) {
        throw new Error('WASM image exceeds its byte limit');
      }
      chunks.push(part.value);
    }
  } finally {
    if (!completed) {
      await reader.cancel().catch(() => undefined);
    }
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}
