import { describe, expect, it, vi } from 'vitest';
import { loadLinkMetadata, parseLinkMetadata } from '../src/ui/link-metadata';

const scope = { origin: 'https://app.example.org', slug: 'Work' };

describe('independent link discovery, never authorization', () => {
  it('binds metadata to the exact requested origin and case-sensitive link and copies it', () => {
    const value = {
      scope: { ...scope },
      requestUser: false,
      publishedSlugs: ['Other', 'Manage/Team'],
    };
    const metadata = parseLinkMetadata(value, scope);
    value.scope.slug = 'Changed';
    value.publishedSlugs[0] = 'Changed';
    expect(metadata).toEqual({
      scope,
      requestUser: false,
      publishedSlugs: ['Other', 'Manage/Team'],
    });
    expect(Object.isFrozen(metadata.scope)).toBe(true);
    expect(Object.isFrozen(metadata.publishedSlugs)).toBe(true);
    expect(parseLinkMetadata({ scope, requestUser: true }, scope).publishedSlugs).toEqual([]);
  });
  for (const value of [
    null,
    [],
    {},
    { scope: { ...scope, slug: 'work' }, requestUser: true },
    { scope: { ...scope, origin: 'https://other.example.org' }, requestUser: true },
    { scope, requestUser: 'true' },
    ...[
      null,
      ['//other.example.org'],
      ['../Private'],
      ['%2fPrivate'],
      Array(1025).fill('Other'),
    ].map((links) => ({ scope, requestUser: true, publishedSlugs: links })),
  ]) {
    it('rejects mismatched scopes, malformed requests and unbounded/non-path discovery', () => {
      expect(() => parseLinkMetadata(value, scope)).toThrow();
    });
  }
  it('rejects a foreign origin before any request, without a bearer/cookie fallback', async () => {
    const transport = vi.fn();
    await expect(loadLinkMetadata(scope, undefined, transport)).rejects.toMatchObject({
      code: 'unavailable',
    });
    expect(transport).not.toHaveBeenCalled();
  });
});
