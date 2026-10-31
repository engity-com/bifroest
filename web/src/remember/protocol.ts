export interface Scope {
  readonly origin: string;
  readonly slug: string;
}

export interface Binding {
  readonly flow: string;
  readonly sessionId: string;
  readonly bindingId: string;
}

export class RememberMeError extends Error {
  constructor(
    readonly code:
      | 'opt-in-required'
      | 'unavailable'
      | 'changed'
      | 'invalid-proof'
      | 'denied'
      | 'rate-limited'
      | 'cancelled'
      | 'outcome-unknown'
      | 'already-remembered'
      | 'busy'
      | 'login-unknown'
      | 'invalid-step'
      | 'key-import'
      | 'artifact-too-large'
      | 'management-unknown',
  ) {
    // Never expose a browser/provider/storage error or persisted plaintext.
    super(`Browser RememberMe: ${code}`);
    this.name = 'RememberMeError';
  }
}

export function validateScope(scope: Scope): void {
  let parsed: URL;
  try {
    if (
      scope === null ||
      typeof scope !== 'object' ||
      Object.keys(scope).sort().join(',') !== 'origin,slug' ||
      typeof scope.origin !== 'string' ||
      typeof scope.slug !== 'string'
    ) {
      throw new Error();
    }
    parsed = new URL(scope.origin);
  } catch {
    throw new RememberMeError('unavailable');
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.origin !== scope.origin ||
    parsed.hostname.endsWith('.') ||
    scope.origin.length > 320 ||
    !/^(?:[a-zA-Z0-9]{1,64}(?:\/[a-zA-Z0-9]{1,64})?)?$/.test(scope.slug)
  ) {
    throw new RememberMeError('unavailable');
  }
}

export function validateBinding(binding: Binding): void {
  if (
    binding === null ||
    typeof binding !== 'object' ||
    Object.keys(binding).sort().join(',') !== 'bindingId,flow,sessionId' ||
    typeof binding.flow !== 'string' ||
    typeof binding.sessionId !== 'string' ||
    typeof binding.bindingId !== 'string' ||
    !/^[a-zA-Z0-9.-]{1,255}$/.test(binding.flow) ||
    binding.flow === '.' ||
    binding.flow === '..' ||
    !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(binding.sessionId) ||
    !/^bbr1\.[A-Za-z0-9_-]{43}$/.test(binding.bindingId)
  ) {
    throw new RememberMeError('unavailable');
  }
  try {
    if (
      decode64(`${binding.bindingId.slice(5).replaceAll('-', '+').replaceAll('_', '/')}=`, 32)
        .length !== 32
    ) {
      throw new Error();
    }
  } catch {
    throw new RememberMeError('unavailable');
  }
}

export function encode64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

export function decode64(value: string, maximum: number): Uint8Array<ArrayBuffer> {
  if (value.length > maximum * 2) {
    throw new RememberMeError('invalid-proof');
  }
  try {
    const raw = atob(value);
    const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
    if (bytes.length > maximum || encode64(bytes) !== value) {
      throw new Error();
    }
    return bytes;
  } catch {
    throw new RememberMeError('invalid-proof');
  }
}

export type ProofPurpose = 'enroll' | 'resume' | 'revoke';

// Validate a server challenge's context, but sign its ORIGINAL bytes. This is a
// protocol adapter, not a reimplementation of Go's authorizer or proof verifier.
export function proofBytes(
  encoded: string,
  scope: Scope,
  publicKey: string,
  purpose: ProofPurpose,
  binding?: Binding,
): Uint8Array<ArrayBuffer> {
  try {
    if (!['enroll', 'resume', 'revoke'].includes(purpose)) {
      throw new Error();
    }
    const bytes = decode64(encoded, 16 << 10);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const prefix = 'bifroest-browser-remember-v1\0';
    if (!text.startsWith(prefix)) {
      throw new Error();
    }
    const body = JSON.parse(text.slice(prefix.length)) as Record<string, unknown>;
    const names = [
      'purpose',
      'origin',
      'slug',
      'flow',
      'sessionId',
      'bindingId',
      'revision',
      'target',
      'publicKey',
      'nonce',
      'expiresAt',
    ];
    if (
      body === null ||
      Array.isArray(body) ||
      typeof body !== 'object' ||
      Object.keys(body).length !== names.length ||
      !names.every((name) => Object.hasOwn(body, name)) ||
      body.purpose !== purpose ||
      body.origin !== scope.origin ||
      body.slug !== scope.slug ||
      body.publicKey !== publicKey ||
      typeof body.flow !== 'string' ||
      typeof body.sessionId !== 'string' ||
      typeof body.target !== 'string' ||
      !/^[0-9a-f]{64}$/.test(body.target) ||
      typeof body.nonce !== 'string' ||
      decode64(body.nonce, 32).length !== 32 ||
      typeof body.expiresAt !== 'string' ||
      !Number.isFinite(Date.parse(body.expiresAt))
    ) {
      throw new Error();
    }
    if (purpose === 'enroll') {
      if (binding !== undefined || body.bindingId !== '' || body.revision !== 0) {
        throw new Error();
      }
      validateBinding({
        flow: body.flow,
        sessionId: body.sessionId,
        bindingId: `bbr1.${'A'.repeat(43)}`,
      });
    } else {
      if (
        binding === undefined ||
        body.flow !== binding.flow ||
        body.sessionId !== binding.sessionId ||
        body.bindingId !== binding.bindingId ||
        !Number.isSafeInteger(body.revision) ||
        (body.revision as number) < 1
      ) {
        throw new Error();
      }
    }
    // Server time/expiry remains authoritative; client wall-clock skew is not
    // used to extend a challenge or reconstruct the bytes signed above.
    return bytes;
  } catch {
    throw new RememberMeError('invalid-proof');
  }
}
