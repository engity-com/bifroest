// Provider text is never HTML or an automatic navigation. Offer only explicit
// HTTPS links without embedded credentials; keep the original message visible.
export function verificationLink(message: string): string | null {
  for (const value of message.match(/\bhttps:\/\/[^\s<>"']+/gu) ?? []) {
    try {
      const parsed = new URL(value);
      if (parsed.protocol === 'https:' && parsed.username === '' && parsed.password === '' && parsed.hostname !== '') return parsed.href;
    } catch { /* A malformed provider string stays plain text. */ }
  }
  return null;
}
