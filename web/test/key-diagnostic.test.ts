import { describe, expect, it } from 'vitest';
import { KeyLoginError, keyLoginDiagnostic, keyLoginError } from '../src/login/diagnostic';
import { RememberMeError } from '../src/remember/protocol';

describe('allowlisted local key diagnostics, never arbitrary internal errors', () => {
  it('retains only phase/code and drops raw exceptions and attached secret fields', () => {
    const secret = 'PRIVATE-KEY-PASSPHRASE-SENTINEL';
    const error = Object.assign(new Error(secret), { privateKey: secret, cause: secret });
    const classified = keyLoginError(error, 'worker-start');
    expect(keyLoginDiagnostic(classified)).toEqual({ phase: 'worker-start', code: 'key-import' });
    expect(JSON.stringify(classified)).not.toContain(secret);
    expect(JSON.stringify(keyLoginDiagnostic(classified))).not.toContain(secret);
    expect(classified.message).not.toContain(secret);
    expect(Object.hasOwn(classified, 'cause')).toBe(false);
    expect(keyLoginDiagnostic(error)).toBeUndefined();
  });
  it('preserves outcome-unknown, denial, cancellation and the deepest known phase', () => {
    for (const code of ['denied', 'login-unknown', 'outcome-unknown'] as const) {
      expect(keyLoginError(new RememberMeError(code), 'authentication').code).toBe(code);
    }
    const cancelled = new RememberMeError('cancelled');
    expect(keyLoginError(cancelled, 'key-import')).toBe(cancelled);
    expect(keyLoginDiagnostic(cancelled)).toBeUndefined();
    const local = new KeyLoginError('invalid-proof', 'challenge');
    expect(keyLoginError(local, 'authentication')).toBe(local);
  });
  it('does not render arbitrary phase/code strings even on a malformed error instance', () => {
    expect(
      keyLoginDiagnostic(new KeyLoginError('unavailable', 'PRIVATE-SENTINEL' as never)),
    ).toBeUndefined();
    expect(
      keyLoginDiagnostic(new KeyLoginError('PRIVATE-SENTINEL' as never, 'key-import')),
    ).toBeUndefined();
  });
  it('does not invoke changing code/phase accessors in diagnostic extraction or classification', () => {
    const error = new KeyLoginError('unavailable', 'key-import');
    let reads = 0;
    Object.defineProperty(error, 'code', {
      get: () => (++reads === 1 ? 'unavailable' : 'PRIVATE-SENTINEL'),
    });
    Object.defineProperty(error, 'phase', {
      get: () => {
        reads++;
        return 'PRIVATE-SENTINEL';
      },
    });
    expect(keyLoginDiagnostic(error)).toBeUndefined();
    expect(keyLoginError(error, 'authentication')).toMatchObject({
      code: 'key-import',
      phase: 'authentication',
    });
    expect(reads).toBe(0);
  });
});
