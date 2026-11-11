import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  preferredTheme,
  preferredUsername,
  saveSuccessfulUsername,
  saveThemePreference,
  themePreferenceKey,
  usernamePreferencePrefix,
} from '../src/ui/preferences';

const scope = { origin: location.origin, slug: 'Work' };
function clean() {
  for (const key of Object.keys(localStorage)) {
    if (key === themePreferenceKey || key.startsWith(usernamePreferencePrefix)) {
      localStorage.removeItem(key);
    }
  }
}
beforeEach(clean);
afterEach(() => {
  vi.restoreAllMocks();
  clean();
});

describe('explicit non-authentication UI preferences', () => {
  it('stores only a theme and original requested name, scoped per origin/flow', () => {
    saveThemePreference('dark');
    saveSuccessfulUsername(scope, 'DOMAIN\\Alice Smith');
    expect(preferredTheme()).toBe('dark');
    expect(preferredUsername(scope)).toBe('DOMAIN\\Alice Smith');
    expect(preferredUsername({ ...scope, slug: 'Other' })).toBe('');
    expect(preferredUsername({ ...scope, origin: 'https://foreign.invalid' })).toBe('');
    expect(Object.keys(localStorage).sort()).toEqual(
      [themePreferenceKey, `${usernamePreferencePrefix}Work`].sort(),
    );
    expect(Object.values(localStorage).sort()).toEqual(['dark', 'DOMAIN\\Alice Smith'].sort());
  });
  it('ignores malformed stored input without interpreting it as identity or authorization', () => {
    localStorage.setItem(themePreferenceKey, 'PRIVATE-INVALID');
    localStorage.setItem(`${usernamePreferencePrefix}Work`, '\ninvalid');
    expect(preferredTheme()).toBe('auto');
    expect(preferredUsername(scope)).toBe('');
    saveSuccessfulUsername(scope, '');
    saveSuccessfulUsername(scope, '   ');
    saveSuccessfulUsername(scope, 'A'.repeat(257));
    expect(localStorage.getItem(`${usernamePreferencePrefix}Work`)).toBe('\ninvalid');
  });
  it('does not let unavailable preference storage block a login or leak storage errors', () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const read = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('PRIVATE-STORAGE');
    });
    expect(preferredTheme()).toBe('auto');
    expect(preferredUsername(scope)).toBe('');
    read.mockRestore();
    const write = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('PRIVATE-STORAGE');
    });
    expect(() => saveThemePreference('dark')).not.toThrow();
    expect(() => saveSuccessfulUsername(scope, 'alice')).not.toThrow();
    write.mockRestore();
    expect(JSON.stringify(log.mock.calls)).not.toContain('PRIVATE-STORAGE');
    expect(localStorage.length).toBe(0);
  });
});
