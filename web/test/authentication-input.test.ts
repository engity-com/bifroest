import { describe, expect, it } from 'vitest';
import type { LoginStep } from '../src/login/interactive';
import { AuthenticationInput, authenticationText } from '../src/login/terminal-input';
import { protectAuthenticationComposition } from '../src/terminal/authentication-composition';

describe('authentication preedit boundary before xterm DOM output', () => {
  it('forwards empty preedit for a secret while preserving public echo and listener cleanup', () => {
    const surface = document.createElement('section');
    const input = document.createElement('textarea');
    const preedit = document.createElement('div');
    surface.append(input, preedit);
    let step: LoginStep = { sequence: '1', kind: 'prompt', message: '', echo: false };
    const guard = protectAuthenticationComposition(
      surface,
      () => step,
      () => {
        throw new Error('unexpected cross-prompt composition');
      },
    );
    const seen: string[] = [];
    input.addEventListener('compositionupdate', (event) => {
      seen.push(event.data);
      preedit.textContent = event.data;
    });
    input.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true }));
    input.dispatchEvent(
      new CompositionEvent('compositionupdate', { bubbles: true, data: 'private-preedit' }),
    );
    expect(seen).toEqual(['']);
    expect(preedit.textContent).toBe('');
    guard.dispose();
    step = { sequence: '2', kind: 'prompt', message: '', echo: true };
    const publicGuard = protectAuthenticationComposition(
      surface,
      () => step,
      () => {
        throw new Error('unexpected cross-prompt composition');
      },
    );
    input.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true }));
    input.dispatchEvent(
      new CompositionEvent('compositionupdate', { bubbles: true, data: 'public-preedit' }),
    );
    expect(preedit.textContent).toBe('public-preedit');
    publicGuard.dispose();
    input.dispatchEvent(
      new CompositionEvent('compositionupdate', { bubbles: true, data: 'after-unmount' }),
    );
    expect(preedit.textContent).toBe('after-unmount');
  });
  it('retires an old secret composition before a new public prompt can inherit its echo or delayed end', () => {
    const surface = document.createElement('section');
    const input = document.createElement('textarea');
    surface.append(input);
    let step: LoginStep = { sequence: '1', kind: 'prompt', message: '', echo: false };
    let rejected = 0;
    const updates: string[] = [];
    let ends = 0;
    const guard = protectAuthenticationComposition(
      surface,
      () => step,
      () => rejected++,
    );
    input.addEventListener('compositionupdate', (event) => updates.push(event.data));
    input.addEventListener('compositionend', () => ends++);
    input.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true }));
    expect(guard.pending()).toBe(true);
    step = { sequence: '2', kind: 'prompt', message: '', echo: true };
    input.dispatchEvent(
      new CompositionEvent('compositionupdate', { bubbles: true, data: 'old-secret' }),
    );
    input.dispatchEvent(
      new CompositionEvent('compositionend', { bubbles: true, data: 'old-secret' }),
    );
    expect(rejected).toBe(1);
    expect(updates).toEqual(['']);
    expect(ends).toBe(0);
    guard.dispose();
  });
});

describe('local authentication prompt input, not primary authentication', () => {
  it('never echoes a secret and never reuses a pasted tail or late answer', () => {
    const editor = new AuthenticationInput();
    editor.reset({ sequence: '1', kind: 'prompt', message: 'Password:', echo: false });
    expect(editor.consume('private-secret')).toEqual({ display: '' });
    expect(editor.consume('\r\nnot-the-next-answer')).toEqual({
      display: '\r\n',
      answer: 'private-secret',
    });
    expect(editor.consume('late')).toEqual({ display: '' });
    editor.reset({ sequence: '2', kind: 'prompt', message: 'Code:', echo: false });
    expect(editor.consume('\r')).toEqual({ display: '\r\n', answer: '' });
  });
  it('honors explicit echo and code-point deletion without retaining the answer after clear', () => {
    const editor = new AuthenticationInput();
    editor.reset({ sequence: '1', kind: 'prompt', message: 'Name:', echo: true });
    expect(editor.consume('A€\x7fB\r')).toEqual({ display: 'A€\b \bB\r\n', answer: 'AB' });
    editor.reset({ sequence: '2', kind: 'prompt', message: 'Secret:', echo: false });
    editor.consume('discard');
    editor.clear();
    expect(editor.consume('\r')).toEqual({ display: '' });
  });
  it('acknowledges info only on Enter, and cancels locally on Ctrl+C/D', () => {
    const editor = new AuthenticationInput();
    editor.reset({ sequence: '1', kind: 'info', message: 'Open the provider', echo: false });
    expect(editor.consume('not-a-credential\r')).toEqual({ display: '\r\n', answer: '' });
    expect(editor.consume('\x03')).toEqual({ display: '\r\n', cancelled: true });
    expect(editor.consume('\x04')).toEqual({ display: '\r\n', cancelled: true });
  });
  it('bounds UTF-8 input and ignores terminal control sequences', () => {
    const editor = new AuthenticationInput();
    editor.reset({ sequence: '1', kind: 'prompt', message: '', echo: false });
    expect(editor.consume('\x1b[A')).toEqual({ display: '' });
    expect(editor.consume('€'.repeat(1366))).toMatchObject({ cancelled: true, limited: true });
    expect(editor.consume('\r')).toEqual({ display: '' });
  });
  it('renders provider controls visibly instead of interpreting terminal escape programs', () => {
    const text = authenticationText('Info\r\n\x1b]52;c;secret\x07\b\rnext');
    expect(text).toBe('Info\r\n␛]52;c;secret␇␈\r\nnext');
    expect(text).not.toContain('\x1b');
    expect(text).not.toContain('\x07');
  });
});
