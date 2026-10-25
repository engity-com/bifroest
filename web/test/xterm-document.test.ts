import { describe, expect, it } from 'vitest';
import { fixXtermDocument, xtermDocumentPlugin } from '../scripts/xterm-document.mjs';

describe('locked xterm documentOverride correction', () => {
  it('fixes only the reviewed precedence expression and fails on changed/duplicate input', () => {
    const before = 'this._document??typeof window<"u"?window.document:null';
    expect(fixXtermDocument(`prefix,${before},suffix`)).toBe(
      'prefix,this._document??(typeof window<"u"?window.document:null),suffix',
    );
    expect(() => fixXtermDocument('changed upstream code')).toThrow();
    expect(() => fixXtermDocument(`${before},${before}`)).toThrow();
    expect(() => xtermDocumentPlugin('6.1.0')).toThrow();
  });
});
