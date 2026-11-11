import { describe, expect, it } from 'vitest';
import { validateScope } from '../src/remember/protocol';

describe('exact HTTP access scope grammar', () => {
  it.each(['', 'bla-bla', 'Work-1/Team-2', '-'.repeat(64), `${'a'.repeat(64)}/${'b'.repeat(64)}`])(
    'accepts %s without changing it',
    (slug) => {
      const scope = Object.freeze({ origin: 'https://app.example.org:8443', slug });
      expect(() => validateScope(scope)).not.toThrow();
      expect(scope.slug).toBe(slug);
    },
  );

  it.each([
    'foo_bar',
    '.',
    '..',
    'foo.bar',
    'foo/bar/baz',
    'foo/',
    '/foo',
    '%66oo',
    'foo%2fbar',
    'foo\\bar',
    'ä',
    'a'.repeat(65),
  ])('rejects %s', (slug) => {
    expect(() => validateScope({ origin: 'https://app.example.org', slug })).toThrow();
  });
});
