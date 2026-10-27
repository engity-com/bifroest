import type { ArtifactRequest } from '../artifacts/protocol';
import {
  artifactFields,
  maximumTransferImageBytes,
  transferMediaType,
} from '../artifacts/protocol';
import type { Scope } from './protocol';
import { decode64, RememberMeError, validateScope } from './protocol';

export type Transport = typeof fetch;
const maximumResponseBytes = 64 << 10;

export interface ArtifactResponseImage {
  readonly bytes: ArrayBuffer;
  readonly mediaType: string;
  readonly status: number;
}

export function isToken(
  value: unknown,
  prefix: 'bwa1.' | 'bwr1.' | 'bwl1.' | 'bmc1.',
): value is string {
  if (
    typeof value !== 'string' ||
    !value.startsWith(prefix) ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.slice(5))
  ) {
    return false;
  }
  try {
    return (
      decode64(`${value.slice(5).replaceAll('-', '+').replaceAll('_', '/')}=`, 32).length === 32
    );
  } catch {
    return false;
  }
}

export function object(value: unknown, fields: string[]): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(',') !== [...fields].sort().join(',')
  ) {
    throw new RememberMeError('unavailable');
  }
  return value as Record<string, unknown>;
}

export function time(value: unknown): string {
  if (typeof value !== 'string' || value.length > 64 || !Number.isFinite(Date.parse(value))) {
    throw new RememberMeError('unavailable');
  }
  return value;
}

// No retry, redirect, URL credential, cookie, persistence or unbounded response
// body. The native same-origin fetch mode also prevents forwarding a bearer to
// another origin, even if a caller accidentally supplies a foreign scope.
export class Http {
  readonly #scope: Scope;
  readonly #transport: Transport;
  constructor(scope: Scope, transport: Transport = globalThis.fetch.bind(globalThis)) {
    validateScope(scope);
    this.#scope = Object.freeze({ ...scope });
    this.#transport = transport;
  }

  // The response image is provisional, even after HTTP EOF. The owned Go/WASM
  // receiver must still decode exact selectors/data-end/post-driver completion.
  // This first adapter stages only bounded tab memory, never OPFS/IndexedDB.
  async artifactImage(
    request: ArtifactRequest,
    token: string,
    signal: AbortSignal,
  ): Promise<ArtifactResponseImage> {
    const selected = Object.freeze({ ...request }) as ArtifactRequest;
    const fields = artifactFields(selected);
    if (!isToken(token, 'bwa1.')) {
      throw new RememberMeError('unavailable');
    }
    const controller = new AbortController();
    const deadline = AbortSignal.timeout(20_000);
    const stopped = AbortSignal.any([signal, controller.signal, deadline]);
    const url = new URL(
      `/_bifroest/api/v1/management/artifacts/${selected.kind}`,
      this.#scope.origin,
    );
    let response: Response | undefined;
    let reader: ReadableStreamDefaultReader<Uint8Array<ArrayBufferLike>> | undefined;
    let result: ArtifactResponseImage | undefined;
    let failure: RememberMeError | undefined;
    let cancelling: Promise<void> | undefined;
    let closeFailed = false;
    const cancelReader = () => {
      if (reader !== undefined && cancelling === undefined) {
        try {
          cancelling = reader.cancel().catch(() => {
            closeFailed = true;
          });
        } catch {
          closeFailed = true;
          cancelling = Promise.resolve();
        }
      }
    };
    stopped.addEventListener('abort', cancelReader, { once: true });
    try {
      if (stopped.aborted) {
        throw new RememberMeError('cancelled');
      }
      response = await this.#transport(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: transferMediaType,
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ ...fields, slug: this.#scope.slug }),
        credentials: 'omit',
        cache: 'no-store',
        mode: 'same-origin',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: stopped,
      });
      if (stopped.aborted) {
        throw new RememberMeError('cancelled');
      }
      if (
        response.redirected ||
        !['basic', 'default'].includes(response.type) ||
        response.url !== url.href ||
        response.status !== 200
      ) {
        throw new RememberMeError(
          response.status === 401 || response.status === 403
            ? 'denied'
            : response.status === 429
              ? 'rate-limited'
              : 'unavailable',
        );
      }
      if (
        response.headers.get('Content-Type') !== transferMediaType ||
        response.headers.has('Content-Encoding') ||
        response.body === null
      ) {
        throw new RememberMeError('unavailable');
      }
      const declared = response.headers.get('Content-Length');
      if (
        declared !== null &&
        (!/^(0|[1-9][0-9]*)$/u.test(declared) || !Number.isSafeInteger(Number(declared)))
      ) {
        throw new RememberMeError('unavailable');
      }
      if (declared !== null && Number(declared) > maximumTransferImageBytes) {
        throw new RememberMeError('artifact-too-large');
      }
      reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let length = 0;
      while (true) {
        const part = await reader.read();
        if (stopped.aborted) {
          throw new RememberMeError('cancelled');
        }
        if (part.done) {
          break;
        }
        if (!(part.value instanceof Uint8Array)) {
          throw new RememberMeError('unavailable');
        }
        length += part.value.byteLength;
        if (length > maximumTransferImageBytes) {
          throw new RememberMeError('artifact-too-large');
        }
        // Own the image even when an injected test/host stream reuses a buffer.
        chunks.push(new Uint8Array(part.value));
      }
      if (declared !== null && Number(declared) !== length) {
        throw new RememberMeError('unavailable');
      }
      const bytes = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
        chunk.fill(0);
      }
      result = { bytes: bytes.buffer, mediaType: transferMediaType, status: response.status };
    } catch (error) {
      failure = stopped.aborted
        ? new RememberMeError(signal.aborted ? 'cancelled' : 'unavailable')
        : error instanceof RememberMeError
          ? error
          : new RememberMeError('unavailable');
    } finally {
      controller.abort();
      try {
        if (reader !== undefined) {
          cancelReader();
          try {
            await cancelling;
          } finally {
            reader.releaseLock();
          }
        } else if (response?.body !== undefined && response.body !== null) {
          await response.body.cancel();
        }
      } catch {
        failure ??= new RememberMeError('unavailable');
      } finally {
        stopped.removeEventListener('abort', cancelReader);
        if (closeFailed) {
          failure ??= new RememberMeError('unavailable');
        }
      }
    }
    if (failure !== undefined || result === undefined || signal.aborted || deadline.aborted) {
      if (result !== undefined) {
        new Uint8Array(result.bytes).fill(0);
      }
      throw failure ?? new RememberMeError(signal.aborted ? 'cancelled' : 'unavailable');
    }
    return result;
  }

  async post(
    action: string,
    fields: Record<string, string>,
    token: string | undefined,
    status: number,
    signal?: AbortSignal,
  ): Promise<unknown> {
    const allowed = [
      'login/password',
      'login/interactive',
      'login/public-key',
      'login/poll',
      'login/reply',
      'login/cancel',
      'access',
      'logout',
      'remember/enroll',
      'remember/resume',
      'remember/revoke',
      'remember/prove',
    ];
    allowed.push('management/flows/list', 'management/sessions/list', 'management/sessions/show');
    allowed.push('management/auditlogs/list', 'management/recordings/list');
    allowed.push('management/version/show');
    allowed.push(
      'management/sessions/prepare',
      'management/sessions/confirm',
      'management/sessions/cancel',
    );
    if (!allowed.includes(action)) {
      throw new RememberMeError('unavailable');
    }
    const deadline = AbortSignal.timeout(20_000);
    const stopped = signal === undefined ? deadline : AbortSignal.any([signal, deadline]);
    if (stopped.aborted) {
      throw new RememberMeError('cancelled');
    }
    const body = JSON.stringify({ ...fields, slug: this.#scope.slug });
    if (new TextEncoder().encode(body).byteLength > 16 << 10) {
      throw new RememberMeError('unavailable');
    }
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };
    if (token !== undefined) {
      const prefix =
        action === 'remember/prove'
          ? 'bwr1.'
          : ['login/poll', 'login/reply', 'login/cancel'].includes(action)
            ? 'bwl1.'
            : 'bwa1.';
      if (!isToken(token, prefix)) {
        throw new RememberMeError('unavailable');
      }
      headers.Authorization = `Bearer ${token}`;
    }
    let response: Response | undefined;
    let reader: ReadableStreamDefaultReader<Uint8Array<ArrayBufferLike>> | undefined;
    try {
      response = await this.#transport(new URL(`/_bifroest/api/v1/${action}`, this.#scope.origin), {
        method: 'POST',
        headers,
        body,
        credentials: 'omit',
        cache: 'no-store',
        mode: 'same-origin',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: stopped,
      });
      if (stopped.aborted) {
        throw new RememberMeError('cancelled');
      }
      if (response.redirected || response.type === 'opaque' || response.status !== status) {
        throw new RememberMeError(
          response.status === 401 || response.status === 403
            ? 'denied'
            : response.status === 429
              ? 'rate-limited'
              : 'unavailable',
        );
      }
      if (status === 204) {
        return undefined;
      }
      if (
        !/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '') ||
        response.body === null
      ) {
        throw new RememberMeError('unavailable');
      }
      reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let length = 0;
      while (true) {
        const chunk = await reader.read();
        if (stopped.aborted) {
          throw new RememberMeError('cancelled');
        }
        if (chunk.done) {
          break;
        }
        length += chunk.value.byteLength;
        if (length > maximumResponseBytes) {
          throw new RememberMeError('unavailable');
        }
        chunks.push(chunk.value);
      }
      const bytes = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
    } catch (error) {
      if (stopped.aborted) {
        throw new RememberMeError(signal?.aborted ? 'cancelled' : 'unavailable');
      }
      throw error instanceof RememberMeError ? error : new RememberMeError('unavailable');
    } finally {
      if (reader !== undefined) {
        await reader.cancel().catch(() => undefined);
        reader.releaseLock();
      } else if (response?.body !== null && response?.body !== undefined) {
        await response.body.cancel().catch(() => undefined);
      }
    }
  }
}
