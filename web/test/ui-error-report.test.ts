import { afterEach, describe, expect, it, vi } from 'vitest';
import { KeyLoginError } from '../src/login/diagnostic';
import { RememberMeError } from '../src/remember/protocol';
import { reportUiError } from '../src/ui/error-report';
import { required } from './required';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('browser error console without retaining secrets', () => {
  it('logs an Error with the actual public classification, not the raw object or cause', () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const secret = 'PRIVATE-PASSPHRASE-TOKEN-SENTINEL';
    const original = Object.assign(new KeyLoginError('invalid-proof', 'challenge'), {
      privateKey: secret,
      cause: new Error(secret),
    });
    reportUiError('application', original);
    expect(log).toHaveBeenCalledOnce();
    const error = log.mock.calls[0]?.[1] as Error;
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBe(original);
    expect(error).toMatchObject({
      name: 'KeyLoginError',
      code: 'invalid-proof',
      phase: 'challenge',
    });
    expect(error.message).toContain('key/challenge/invalid-proof');
    expect(JSON.stringify(log.mock.calls) + error.stack).not.toContain(secret);
    expect(Object.hasOwn(error, 'cause')).toBe(false);
  });
  it('preserves only already loaded public asset callsites, not messages, names or arbitrary URLs', () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const asset = `${location.origin}/_bifroest/files/assets/index-PUBLIC.js`;
    vi.spyOn(performance, 'getEntriesByType').mockReturnValue([
      { name: asset },
    ] as PerformanceEntry[]);
    const original = new TypeError('PRIVATE-MESSAGE');
    original.stack = `TypeError: PRIVATE-MESSAGE\n    at PRIVATE-FUNCTION (${asset}:12:34)\n    at x (${location.origin}/PRIVATE-FILENAME:12:34)\n    at x (${asset}?token=PRIVATE-TOKEN:12:34)`;
    reportUiError('artifact', original);
    const error = log.mock.calls[0]?.[1] as Error;
    expect(error).toMatchObject({ name: 'TypeError' });
    expect(error.stack).toContain('/_bifroest/files/assets/index-PUBLIC.js:12:34');
    expect(JSON.stringify(log.mock.calls) + error.stack).not.toContain('PRIVATE-');
  });
  it('does not let console/performance failure change application behavior or hide unknown mutation outcomes', () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(performance, 'getEntriesByType').mockImplementation(() => {
      throw new Error('PRIVATE-PERFORMANCE');
    });
    reportUiError('management-mutation', new RememberMeError('cancelled'), 'mutation-unknown');
    expect(log).toHaveBeenCalledOnce();
    expect(log.mock.calls[0]?.[1]).toMatchObject({ code: 'cancelled', reason: 'mutation-unknown' });
    log.mockImplementation(() => {
      throw new Error('console failed');
    });
    expect(() => reportUiError('application', new Error('PRIVATE'))).not.toThrow();
  });
  it('does not label ordinary user cancellation as an error', () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    reportUiError('application', new RememberMeError('cancelled'));
    expect(log).not.toHaveBeenCalled();
  });
  it('does not execute an arbitrary stack getter or retain an error cause', () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const getter = vi.fn(() => 'PRIVATE-STACK');
    const original = new Error('PRIVATE-MESSAGE');
    Object.defineProperty(original, 'stack', { get: getter });
    reportUiError('application', original);
    expect(getter).not.toHaveBeenCalled();
    expect(log).toHaveBeenCalledOnce();
    expect((required(log.mock.calls[0])[1] as Error).stack).not.toContain('PRIVATE-');
  });
  it('does not read a changing code accessor or copy a secret/key reference from it', () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const original = new RememberMeError('unavailable');
    const getter = vi.fn().mockReturnValueOnce('unavailable').mockReturnValue('PRIVATE-SENTINEL');
    Object.defineProperty(original, 'code', { get: getter });
    reportUiError('application', original);
    expect(getter).not.toHaveBeenCalled();
    expect(log.mock.calls[0]?.[1]).toMatchObject({ code: 'unavailable' });
    expect(JSON.stringify(log.mock.calls)).not.toContain('PRIVATE-SENTINEL');
  });
  it('does not mistake a bound user-defined stack getter for the native intrinsic', () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const original = new Error();
    const getter = vi.fn(() => 'PRIVATE-SENTINEL');
    Object.defineProperty(original, 'stack', { get: getter.bind(null) });
    reportUiError('application', original);
    expect(getter).not.toHaveBeenCalled();
    expect(log).toHaveBeenCalledOnce();
  });
});
