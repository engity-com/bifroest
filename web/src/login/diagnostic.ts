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
  if (
    error instanceof KeyLoginError ||
    (error instanceof RememberMeError && error.code === 'cancelled')
  ) {
    return error;
  }
  return new KeyLoginError(error instanceof RememberMeError ? error.code : fallback, phase);
}

export interface KeyLoginDiagnostic {
  readonly phase: KeyLoginPhase;
  readonly code: Code;
}
export function keyLoginDiagnostic(error: unknown): KeyLoginDiagnostic | undefined {
  if (
    !(error instanceof KeyLoginError) ||
    !phases.includes(error.phase) ||
    !codes.includes(error.code)
  ) {
    return undefined;
  }
  return Object.freeze({ phase: error.phase, code: error.code });
}
