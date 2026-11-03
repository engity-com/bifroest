import { describe, expect, it, vi } from 'vitest';
import {
  linkSlugs,
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
      rootAvailable: false,
      frontendAvailable: true,
      loginOptions: [inputOption],
      publishedSlugs: ['Other', 'Manage/Team'],
    };
    const metadata = parseLinkMetadata(value, scope);
    value.scope.slug = 'Changed';
    value.rootAvailable = true;
    value.publishedSlugs[0] = 'Changed';
    inputOption.requestUser = false;
    expect(metadata).toEqual({
      scope,
      rootAvailable: false,
      loginOptions: [option],
      publishedSlugs: ['Other', 'Manage/Team'],
    });
    expect(Object.isFrozen(metadata.scope)).toBe(true);
    expect(Object.isFrozen(metadata)).toBe(true);
    expect(Object.isFrozen(metadata.publishedSlugs)).toBe(true);
    expect(Object.isFrozen(metadata.loginOptions)).toBe(true);
    expect(Object.isFrozen(metadata.loginOptions[0])).toBe(true);
    expect(
      parseLinkMetadata({ scope, loginOptions: [], rootAvailable: false }, scope).publishedSlugs,
    ).toEqual([]);
  });
  for (const value of [
    null,
    [],
    {},
    { scope: { ...scope, slug: 'work' }, loginOptions: [option], rootAvailable: false },
    {
      scope: { ...scope, origin: 'https://other.example.org' },
      loginOptions: [option],
      rootAvailable: false,
    },
    { scope, requestUser: true },
    { scope, loginOptions: [option] },
    { scope, loginOptions: [option], rootAvailable: 'false' },
    { scope, loginOptions: [option], rootAvailable: null },
    { scope, loginOptions: [option], rootAvailable: false, token: 'untrusted' },
    { scope, loginOptions: [option], rootAvailable: false, frontendAvailable: 'true' },
    ...[
      null,
      ['//other.example.org'],
      ['../Private'],
      ['%2fPrivate'],
      ['foo_bar'],
      [''],
      Array(1025).fill('Other'),
    ].map((links) => ({
      scope,
      loginOptions: [option],
      publishedSlugs: links,
      rootAvailable: false,
    })),
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
    ].map((loginOptions) => ({ scope, loginOptions, rootAvailable: false })),
  ]) {
    it('rejects mismatched scopes, malformed requests and unbounded/non-path discovery', () => {
      expect(() => parseLinkMetadata(value, scope)).toThrow();
    });
  }
  it('keeps name modes separate and certificate requirements bound to public-key options', () => {
    const metadata = parseLinkMetadata(
      {
        scope,
        rootAvailable: true,
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

  it('preserves hyphenated aliases without substituting a published flow name', () => {
    const alias = { ...scope, slug: 'bla-bla' };
    const metadata = parseLinkMetadata(
      {
        scope: alias,
        rootAvailable: false,
        loginOptions: [option],
        publishedSlugs: ['docker', 'other-alias/Team-1'],
      },
      alias,
    );
    expect(metadata.scope.slug).toBe('bla-bla');
    expect(linkSlugs(metadata, metadata, 'bla-bla', [])).toEqual([
      'bla-bla',
      'docker',
      'other-alias/Team-1',
    ]);
  });

  it.each([false, true])(
    'selects root only with the explicit rootAvailable=%s flag',
    (rootAvailable) => {
      const initial = parseLinkMetadata(
        {
          scope: { ...scope, slug: '' },
          loginOptions: [],
          publishedSlugs: ['Work'],
          rootAvailable: false,
        },
        { ...scope, slug: '' },
      );
      const current = { ...initial, rootAvailable };
      const slugs = linkSlugs(initial, current, '', [
        { ...scope, slug: '' },
        { ...scope, slug: 'bla-bla' },
        { origin: 'https://foreign.example.org', slug: 'Private' },
      ]);
      expect(slugs.includes('')).toBe(rootAvailable);
      expect(slugs).toContain('Work');
      expect(slugs).toContain('bla-bla');
      expect(slugs).not.toContain('Private');
    },
  );
});
