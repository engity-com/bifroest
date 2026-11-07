// Remote titles are untrusted text, never markup, identity or navigation. Keep
// them short and remove control/bidi formatting that could disguise a tab.
export function tabTitle(value: string): string {
  return [...value.replace(/[\p{Cc}\p{Cf}]/gu, '').trim()].slice(0, 160).join('');
}
