// xterm 6.0.0 CoreBrowserTerminal.open loses documentOverride in the
// CoreBrowserService argument because (a ?? b) ? c : d wins over a ?? (b ? c : d).
// Fix only this known expression during bundling; never mutate node_modules,
// global document factories, or CSP. Upgrades must review/remove this guard.
export function fixXtermDocument(code) {
  const before = 'this._document??typeof window<"u"?window.document:null';
  if (code.split(before).length !== 2) {
    throw new Error('xterm documentOverride patch needs review');
  }
  return code.replace(before, 'this._document??(typeof window<"u"?window.document:null)');
}

export function xtermDocumentPlugin(version) {
  if (version !== '6.0.0') {
    throw new Error('xterm version changed; documentOverride patch needs review');
  }
  return {
    name: 'xterm-6-document-override',
    enforce: 'pre',
    transform(code, id) {
      if (
        !id.replaceAll('\\', '/').split('?')[0].endsWith('/node_modules/@xterm/xterm/lib/xterm.mjs')
      ) {
        return;
      }
      return { code: fixXtermDocument(code), map: null };
    },
  };
}
