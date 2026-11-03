import type { Scope } from '../remember';
import { RememberMeError, validateScope } from '../remember/protocol';

export type LoginMethod = 'password' | 'keyboard-interactive' | 'public-key' | 'none';

export interface LoginOption {
  readonly method: LoginMethod;
  readonly requestUser: boolean;
  readonly certificateRequired: boolean;
}

export interface LinkMetadata {
  readonly scope: Scope;
  readonly loginOptions: readonly LoginOption[];
  readonly publishedSlugs: readonly string[];
  readonly rootAvailable: boolean;
}

// The directory itself is never a selectable root access. Only the explicit
// configuration-derived flag permits '', including for old root tab scopes.
export function linkSlugs(
  initial: LinkMetadata,
  current: LinkMetadata,
  routeSlug: string | null,
  tabScopes: readonly Scope[],
): string[] {
  return [
    ...new Set([
      initial.scope.slug,
      ...initial.publishedSlugs,
      current.scope.slug,
      ...current.publishedSlugs,
      ...(current.rootAvailable ? [''] : []),
      ...(routeSlug === null ? [] : [routeSlug]),
      ...tabScopes
        .filter((scope) => scope.origin === current.scope.origin)
        .map((scope) => scope.slug),
    ]),
  ].filter((slug) => slug !== '' || current.rootAvailable);
}

export function loginOptionKey(option: LoginOption): string {
  return `${option.method}:${option.requestUser ? 'named' : 'nameless'}`;
}

export function loginOptionFor(metadata: LinkMetadata, key: string): LoginOption | null {
  return metadata.loginOptions.find((option) => loginOptionKey(option) === key) ?? null;
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
    Object.keys(body).some(
      (key) =>
        !['scope', 'loginOptions', 'publishedSlugs', 'rootAvailable', 'frontendAvailable'].includes(
          key,
        ),
    ) ||
    selected === null ||
    typeof selected !== 'object' ||
    Array.isArray(selected) ||
    Object.keys(selected).sort().join(',') !== 'origin,slug' ||
    selected.origin !== scope.origin ||
    selected.slug !== scope.slug ||
    typeof body.rootAvailable !== 'boolean' ||
    (body.frontendAvailable !== undefined && typeof body.frontendAvailable !== 'boolean') ||
    !Array.isArray(body.loginOptions) ||
    body.loginOptions.length > 8
  ) {
    throw new RememberMeError('unavailable');
  }
  const optionKeys = new Set<string>();
  const options = body.loginOptions.map((value: unknown): LoginOption => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      throw new RememberMeError('unavailable');
    }
    const option = value as Record<string, unknown>;
    if (
      Object.keys(option).sort().join(',') !== 'certificateRequired,method,requestUser' ||
      !['password', 'keyboard-interactive', 'public-key', 'none'].includes(
        option.method as string,
      ) ||
      typeof option.requestUser !== 'boolean' ||
      typeof option.certificateRequired !== 'boolean' ||
      (option.method !== 'public-key' && option.certificateRequired)
    ) {
      throw new RememberMeError('unavailable');
    }
    const decoded = Object.freeze({
      method: option.method as LoginMethod,
      requestUser: option.requestUser,
      certificateRequired: option.certificateRequired,
    });
    const key = loginOptionKey(decoded);
    if (optionKeys.has(key)) {
      throw new RememberMeError('unavailable');
    }
    optionKeys.add(key);
    return decoded;
  });
  const links = body.publishedSlugs === undefined ? [] : body.publishedSlugs;
  if (
    !Array.isArray(links) ||
    links.length > 1024 ||
    !links.every(
      (slug) =>
        typeof slug === 'string' && /^[A-Za-z0-9-]{1,64}(?:\/[A-Za-z0-9-]{1,64})?$/.test(slug),
    )
  ) {
    throw new RememberMeError('unavailable');
  }
  return Object.freeze({
    scope: Object.freeze({ ...scope }),
    loginOptions: Object.freeze(options),
    publishedSlugs: Object.freeze([...links]),
    rootAvailable: body.rootAvailable,
  });
}
