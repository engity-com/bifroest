// A bounded public WASM image is still only transport input, not a signature or
// producer-trust proof. The caller retains status/type/origin checks and the Go
// runtime owns key import and challenge verification.
export async function readBoundedWasmBody(
  body: ReadableStream<Uint8Array>,
  cancelOtherBranch?: () => Promise<void>,
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
      // When validating a cloned response, either tee cancellation alone can
      // wait for the other branch. Start both attempts before joining them.
      await Promise.allSettled([
        Promise.resolve().then(() => reader.cancel()),
        Promise.resolve().then(() => cancelOtherBranch?.()),
      ]);
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

// Consume the *original fetch response* through the browser's native body
// consumer only after a clone has bounded the entire accepted image. An
// unchecked arrayBuffer() must never run in parallel or replace the preflight.
// Oversize stops validation and cancels both branches before native consumption.
// This is transport framing, not WASM authenticity or artifact verification.
export async function readBoundedWasmResponse(
  response: Response,
  abortIncomplete: () => void,
): Promise<ArrayBuffer> {
  let cancelled: Promise<void> | undefined;
  const cancelOriginal = () => {
    cancelled ??= (async () => {
      try {
        abortIncomplete();
      } finally {
        await response.body?.cancel();
      }
    })().catch(() => undefined);
    return cancelled;
  };
  try {
    const checking = response.clone();
    if (checking.body === null) {
      throw new Error('WASM response has no body');
    }
    const checked = await readBoundedWasmBody(checking.body, cancelOriginal);
    const bytes = await response.arrayBuffer();
    if (!(bytes instanceof ArrayBuffer) || bytes.byteLength !== checked.byteLength) {
      throw new Error('WASM response length changed');
    }
    return bytes;
  } catch (error) {
    await cancelOriginal();
    throw error;
  }
}
