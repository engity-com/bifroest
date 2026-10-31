import type { Scope } from '../remember';
import { RememberMeError, validateScope } from '../remember/protocol';

export interface LinkMetadata {
  readonly scope: Scope;
  readonly requestUser: boolean;
  readonly publishedSlugs: readonly string[];
}

// Discovery is not authorization. Each new link gets its own bounded metadata
// request and BrowserClient; never reinterpret an existing access for that link.
export async function loadLinkMetadata(
  scope: Scope,
  signal?: AbortSignal,
  transport: typeof fetch = globalThis.fetch.bind(globalThis),
): Promise<LinkMetadata> {
  validateScope(scope);
  if (scope.origin !== location.origin) {
    throw new RememberMeError('unavailable');
  }
  const stopped = signal
    ? AbortSignal.any([signal, AbortSignal.timeout(20_000)])
    : AbortSignal.timeout(20_000);
  if (stopped.aborted) {
    throw new RememberMeError('cancelled');
  }
  const response = await transport(new URL(`/${scope.slug}`, scope.origin), {
    headers: { Accept: 'application/json' },
    credentials: 'omit',
    cache: 'no-store',
    mode: 'same-origin',
    redirect: 'error',
    signal: stopped,
  });
  if (
    !response.ok ||
    response.redirected ||
    !response.headers.get('Content-Type')?.startsWith('application/json') ||
    response.body === null
  ) {
    await response.body?.cancel();
    throw new RememberMeError('unavailable');
  }
  const reader = response.body.getReader();
  const abort = () => {
    void reader.cancel().catch(() => undefined);
  };
  stopped.addEventListener('abort', abort, { once: true });
  const chunks: Uint8Array[] = [];
  let length = 0;
  let complete = false;
  try {
    while (true) {
      if (stopped.aborted) {
        throw new RememberMeError('cancelled');
      }
      const chunk = await reader.read();
      if (chunk.done) {
        complete = true;
        break;
      }
      length += chunk.value.byteLength;
      if (length > 64 << 10) {
        throw new RememberMeError('unavailable');
      }
      chunks.push(chunk.value);
    }
  } finally {
    stopped.removeEventListener('abort', abort);
    if (!complete) {
      await reader.cancel().catch(() => undefined);
    }
    reader.releaseLock();
  }
  if (stopped.aborted) {
    throw new RememberMeError('cancelled');
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return parseLinkMetadata(
    JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)),
    scope,
  );
}

export function parseLinkMetadata(value: unknown, scope: Scope): LinkMetadata {
  validateScope(scope);
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new RememberMeError('unavailable');
  }
  const body = value as Record<string, unknown>;
  const selected = body.scope as Record<string, unknown> | null;
  if (
    selected === null ||
    typeof selected !== 'object' ||
    selected.origin !== scope.origin ||
    selected.slug !== scope.slug ||
    typeof body.requestUser !== 'boolean'
  ) {
    throw new RememberMeError('unavailable');
  }
  const links = body.publishedSlugs === undefined ? [] : body.publishedSlugs;
  if (
    !Array.isArray(links) ||
    links.length > 1024 ||
    !links.every(
      (slug) =>
        typeof slug === 'string' && /^[A-Za-z0-9]{1,64}(?:\/[A-Za-z0-9]{1,64})?$/.test(slug),
    )
  ) {
    throw new RememberMeError('unavailable');
  }
  return Object.freeze({
    scope: Object.freeze({ ...scope }),
    requestUser: body.requestUser,
    publishedSlugs: Object.freeze([...links]),
  });
}
