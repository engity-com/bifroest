import { decode64, RememberMeError, validateScope } from './protocol';
import type { Scope } from './protocol';

export type Transport = typeof fetch;
const maximumResponseBytes = 64 << 10;

export function isToken(value: unknown, prefix: 'bwa1.' | 'bwr1.' | 'bwl1.'): value is string {
  if (typeof value !== 'string' || !value.startsWith(prefix) || !/^[A-Za-z0-9_-]{43}$/.test(value.slice(5))) return false;
  try { return decode64(value.slice(5).replaceAll('-', '+').replaceAll('_', '/') + '=', 32).length === 32; }
  catch { return false; }
}

export function object(value: unknown, fields: string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== [...fields].sort().join(',')) throw new RememberMeError('unavailable');
  return value as Record<string, unknown>;
}

export function time(value: unknown): string {
  if (typeof value !== 'string' || value.length > 64 || !Number.isFinite(Date.parse(value))) throw new RememberMeError('unavailable');
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

  async post(action: string, fields: Record<string, string>, token: string | undefined, status: number, signal?: AbortSignal): Promise<unknown> {
    const allowed = ['login/password', 'login/interactive', 'login/public-key', 'login/poll', 'login/reply', 'login/cancel', 'access', 'logout', 'remember/enroll', 'remember/resume', 'remember/revoke', 'remember/prove'];
    if (!allowed.includes(action)) throw new RememberMeError('unavailable');
    const deadline = AbortSignal.timeout(20_000);
    const stopped = signal === undefined ? deadline : AbortSignal.any([signal, deadline]);
    if (stopped.aborted) throw new RememberMeError('cancelled');
    const body = JSON.stringify({ ...fields, slug: this.#scope.slug });
    if (new TextEncoder().encode(body).byteLength > 16 << 10) throw new RememberMeError('unavailable');
    const headers: Record<string, string> = { 'Content-Type': 'application/json', Accept: 'application/json' };
    if (token !== undefined) {
      const prefix = action === 'remember/prove' ? 'bwr1.' : ['login/poll', 'login/reply', 'login/cancel'].includes(action) ? 'bwl1.' : 'bwa1.';
      if (!isToken(token, prefix)) throw new RememberMeError('unavailable');
      headers.Authorization = `Bearer ${token}`;
    }
    let response: Response | undefined;
    let reader: ReadableStreamDefaultReader<Uint8Array<ArrayBufferLike>> | undefined;
    try {
      response = await this.#transport(new URL(`/_bifroest/api/v1/${action}`, this.#scope.origin), {
        method: 'POST', headers, body,
        credentials: 'omit', cache: 'no-store', mode: 'same-origin', redirect: 'error', referrerPolicy: 'no-referrer', signal: stopped,
      });
      if (stopped.aborted) throw new RememberMeError('cancelled');
      if (response.redirected || response.type === 'opaque' || response.status !== status) {
        throw new RememberMeError(response.status === 401 || response.status === 403 ? 'denied' : response.status === 429 ? 'rate-limited' : 'unavailable');
      }
      if (status === 204) return undefined;
      if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '') || response.body === null) throw new RememberMeError('unavailable');
      reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let length = 0;
      while (true) {
        const chunk = await reader.read();
        if (stopped.aborted) throw new RememberMeError('cancelled');
        if (chunk.done) break;
        length += chunk.value.byteLength;
        if (length > maximumResponseBytes) throw new RememberMeError('unavailable');
        chunks.push(chunk.value);
      }
      const bytes = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
    } catch (error) {
      if (stopped.aborted) throw new RememberMeError(signal?.aborted ? 'cancelled' : 'unavailable');
      throw error instanceof RememberMeError ? error : new RememberMeError('unavailable');
    } finally {
      if (reader !== undefined) { await reader.cancel().catch(() => undefined); reader.releaseLock(); }
      else if (response?.body !== null && response?.body !== undefined) await response.body.cancel().catch(() => undefined);
    }
  }
}
