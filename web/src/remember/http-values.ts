import { decode64, RememberMeError } from './protocol';

// Protocol validation also used by workers, without document/network clients.
export function isToken(
    value: unknown,
    prefix: 'bwa1.' | 'bwr1.' | 'bwl1.' | 'bmc1.',
): value is string {
    if (
        typeof value !== 'string' ||
        !value.startsWith(prefix) ||
        !/^[A-Za-z0-9_-]{43}$/.test(value.slice(5))
    ) {
        return false;
    }
    try {
        return (
            decode64(`${value.slice(5).replaceAll('-', '+').replaceAll('_', '/')}=`, 32).length ===
            32
        );
    } catch {
        return false;
    }
}

export function object(value: unknown, fields: string[]): Record<string, unknown> {
    if (
        value === null ||
        typeof value !== 'object' ||
        Array.isArray(value) ||
        Object.keys(value).sort().join(',') !== [...fields].sort().join(',')
    ) {
        throw new RememberMeError('unavailable');
    }
    return value as Record<string, unknown>;
}

export function time(value: unknown): string {
    if (typeof value !== 'string' || value.length > 64 || !Number.isFinite(Date.parse(value))) {
        throw new RememberMeError('unavailable');
    }
    return value;
}
