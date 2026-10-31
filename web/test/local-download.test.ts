import { afterEach, describe, expect, it, vi } from 'vitest';
import { LocalArtifactDownload } from '../src/artifacts/local-download';

afterEach(() => vi.restoreAllMocks());

describe('owned local artifact save URLs (not filesystem write confirmation)', () => {
  it('owns one URL and revokes it on replacement/discard without persisting bytes', () => {
    const create = vi
      .spyOn(URL, 'createObjectURL')
      .mockReturnValueOnce('blob:original')
      .mockReturnValueOnce('blob:plain');
    const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      expect(this.download).toMatch(/\.(?:bin|cast)$/u);
      expect(document.body.contains(this)).toBe(true);
    });
    const saves = new LocalArtifactDownload();
    saves.save(new Blob(['original']), 'recording.bin');
    expect(create).toHaveBeenCalledOnce();
    expect(revoke).not.toHaveBeenCalled();
    saves.save(new Blob(['verified plaintext']), 'recording.cast');
    expect(revoke).toHaveBeenCalledWith('blob:original');
    expect(click).toHaveBeenCalledTimes(2);
    expect(document.querySelector('a[download]')).toBeNull();
    saves.clear();
    saves.clear();
    expect(revoke.mock.calls).toEqual([['blob:original'], ['blob:plain']]);
  });

  it('refuses path/HTML filenames and releases a failed click without leaking a DOM node or URL', () => {
    const create = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:failed');
    const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {
      throw new Error('private browser detail');
    });
    const saves = new LocalArtifactDownload();
    for (const name of ['../private', '/root', 'x\\y', '<script>', 'x'.repeat(241), '..']) {
      expect(() => saves.save(new Blob(['private']), name)).toThrow(
        'invalid local artifact filename',
      );
    }
    expect(create).not.toHaveBeenCalled();
    expect(() => saves.save(new Blob(['private']), 'audit.jsonl')).toThrow(
      'local artifact save unavailable',
    );
    expect(click).toHaveBeenCalledOnce();
    expect(revoke).toHaveBeenCalledWith('blob:failed');
    expect(document.querySelector('a[download]')).toBeNull();
  });
});
