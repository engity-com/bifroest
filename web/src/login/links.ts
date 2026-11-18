// Extract only HTTPS links without embedded credentials, never HTML. Automatic
// OIDC navigation additionally validates the exact same-origin ticket route.
export function verificationLink(message: string): string | null {
    for (const value of message.match(/\bhttps:\/\/[^\s<>"']+/gu) ?? []) {
        try {
            const parsed = new URL(value);
            if (
                parsed.protocol === 'https:' &&
                parsed.username === '' &&
                parsed.password === '' &&
                parsed.hostname !== ''
            ) {
                return parsed.href;
            }
        } catch {
            /* A malformed provider string stays plain text. */
        }
    }
    return null;
}
