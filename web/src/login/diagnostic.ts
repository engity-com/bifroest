import { RememberMeError } from '../remember/protocol';

const phases = [
  'module',
  'wasm-download',
  'file-read',
  'worker-start',
  'key-import',
  'browser-crypto',
  'challenge',
  'sign',
  'signature',
  'authentication',
] as const;
export type KeyLoginPhase = (typeof phases)[number];
type Code = RememberMeError['code'];
const rememberCodes: readonly Code[] = [
  'opt-in-required',
  'unavailable',
  'changed',
  'invalid-proof',
  'denied',
  'rate-limited',
  'cancelled',
  'outcome-unknown',
  'already-remembered',
  'busy',
  'login-unknown',
  'invalid-step',
  'key-import',
  'artifact-too-large',
  'management-unknown',
];
const codes: readonly Code[] = [
  'unavailable',
  'key-import',
  'invalid-proof',
  'denied',
  'rate-limited',
  'cancelled',
  'login-unknown',
  'invalid-step',
  'busy',
  'outcome-unknown',
];

// Only a local, allowlisted phase/code crosses into UI state. Never retain a
// cause, parser error, filename, key, passphrase, HTTP body, token or stack.
export class KeyLoginError extends RememberMeError {
  constructor(
    code: Code,
    readonly phase: KeyLoginPhase,
  ) {
    super(code);
    this.name = 'KeyLoginError';
  }
}

export function keyLoginError(
  error: unknown,
  phase: KeyLoginPhase,
  fallback: Code = 'key-import',
): RememberMeError {
  const code = publicRememberErrorCode(error);
  if (
    (error instanceof KeyLoginError && keyLoginDiagnostic(error) !== undefined) ||
    (error instanceof RememberMeError && code === 'cancelled')
  ) {
    return error;
  }
  return new KeyLoginError(code ?? fallback, phase);
}

export function publicRememberErrorCode(error: unknown): Code | undefined {
  try {
    if (!(error instanceof RememberMeError)) {
      return undefined;
    }
    const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
    const code: unknown = descriptor && 'value' in descriptor ? descriptor.value : undefined;
    return typeof code === 'string' && rememberCodes.includes(code as Code)
      ? (code as Code)
      : undefined;
  } catch {
    return undefined;
  }
}

export interface KeyLoginDiagnostic {
  readonly phase: KeyLoginPhase;
  readonly code: Code;
}
export function keyLoginDiagnostic(error: unknown): KeyLoginDiagnostic | undefined {
  try {
    if (!(error instanceof KeyLoginError)) {
      return undefined;
    }
    const descriptor = Object.getOwnPropertyDescriptor(error, 'phase');
    const phase: unknown = descriptor && 'value' in descriptor ? descriptor.value : undefined;
    const code = publicRememberErrorCode(error);
    if (
      typeof phase !== 'string' ||
      !phases.includes(phase as KeyLoginPhase) ||
      code === undefined ||
      !codes.includes(code)
    ) {
      return undefined;
    }
    return Object.freeze({ phase: phase as KeyLoginPhase, code });
  } catch {
    return undefined;
  }
}
