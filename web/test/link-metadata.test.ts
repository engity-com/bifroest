import { describe, expect, it, vi } from 'vitest';
import {
  loadLinkMetadata,
  loginOptionFor,
  loginOptionKey,
  parseLinkMetadata,
} from '../src/ui/link-metadata';

const scope = { origin: 'https://app.example.org', slug: 'Work' };
const option = { method: 'password', requestUser: true, certificateRequired: false };

describe('independent link discovery, never authorization', () => {
  it('binds metadata to the exact requested origin and case-sensitive link and copies it', () => {
    const inputOption = { ...option };
    const value = {
      scope: { ...scope },
      loginOptions: [inputOption],
      publishedSlugs: ['Other', 'Manage/Team'],
    };
    const metadata = parseLinkMetadata(value, scope);
    value.scope.slug = 'Changed';
    value.publishedSlugs[0] = 'Changed';
    inputOption.requestUser = false;
    expect(metadata).toEqual({
      scope,
      loginOptions: [option],
      publishedSlugs: ['Other', 'Manage/Team'],
    });
    expect(Object.isFrozen(metadata.scope)).toBe(true);
    expect(Object.isFrozen(metadata.publishedSlugs)).toBe(true);
    expect(Object.isFrozen(metadata.loginOptions)).toBe(true);
    expect(Object.isFrozen(metadata.loginOptions[0])).toBe(true);
    expect(parseLinkMetadata({ scope, loginOptions: [] }, scope).publishedSlugs).toEqual([]);
  });
  for (const value of [
    null,
    [],
    {},
    { scope: { ...scope, slug: 'work' }, loginOptions: [option] },
    { scope: { ...scope, origin: 'https://other.example.org' }, loginOptions: [option] },
    { scope, requestUser: true },
    ...[
      null,
      ['//other.example.org'],
      ['../Private'],
      ['%2fPrivate'],
      Array(1025).fill('Other'),
    ].map((links) => ({ scope, loginOptions: [option], publishedSlugs: links })),
    ...[
      null,
      ['password'],
      [{ ...option, method: 'unknown' }],
      [{ ...option, requestUser: 'true' }],
      [{ ...option, certificateRequired: true }],
      [{ method: 'password', requestUser: true }],
      [{ ...option, token: 'untrusted' }],
      [{ ...option }, { ...option }],
      Array(9).fill(option),
    ].map((loginOptions) => ({ scope, loginOptions })),
  ]) {
    it('rejects mismatched scopes, malformed requests and unbounded/non-path discovery', () => {
      expect(() => parseLinkMetadata(value, scope)).toThrow();
    });
  }
  it('keeps name modes separate and certificate requirements bound to public-key options', () => {
    const metadata = parseLinkMetadata(
      {
        scope,
        loginOptions: [
          option,
          { ...option, requestUser: false },
          { method: 'public-key', requestUser: true, certificateRequired: true },
          { method: 'none', requestUser: false, certificateRequired: false },
        ],
      },
      scope,
    );
    expect(metadata.loginOptions.map(loginOptionKey)).toEqual([
      'password:named',
      'password:nameless',
      'public-key:named',
      'none:nameless',
    ]);
    expect(loginOptionFor(metadata, 'public-key:named')?.certificateRequired).toBe(true);
    expect(loginOptionFor(metadata, 'keyboard-interactive:nameless')).toBeNull();
    expect(loginOptionFor(metadata, 'password:nameless')?.requestUser).toBe(false);
  });
  it('rejects a foreign origin before any request, without a bearer/cookie fallback', async () => {
    const transport = vi.fn();
    await expect(loadLinkMetadata(scope, undefined, transport)).rejects.toMatchObject({
      code: 'unavailable',
    });
    expect(transport).not.toHaveBeenCalled();
  });
});
