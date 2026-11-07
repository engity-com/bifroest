import { RememberMeError } from '../remember/protocol';

// Abortable local Blob read shared by short-lived key/evidence workers. It does
// not submit a form, upload a filename or retain the bytes in application state.
export function readLocalBytes(file: Blob, signal: AbortSignal): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    const cleanup = () => {
      signal.removeEventListener('abort', aborted);
      reader.onload = null;
      reader.onerror = null;
      reader.onabort = null;
    };
    const failed = () => {
      cleanup();
      reject(new RememberMeError('key-import'));
    };
    const aborted = () => {
      cleanup();
      reader.abort();
      reject(new RememberMeError('cancelled'));
    };
    reader.onload = () => {
      const value = reader.result;
      cleanup();
      if (signal.aborted) {
        reject(new RememberMeError('cancelled'));
      } else if (value instanceof ArrayBuffer) {
        resolve(value);
      } else {
        failed();
      }
    };
    reader.onerror = failed;
    reader.onabort = failed;
    signal.addEventListener('abort', aborted, { once: true });
    if (signal.aborted) {
      aborted();
      return;
    }
    try {
      reader.readAsArrayBuffer(file);
    } catch {
      failed();
    }
  });
}
