export type OidcStatus =
    | 'created'
    | 'redirected'
    | 'exchanging'
    | 'approval'
    | 'authorizing'
    | 'accepted'
    | 'denied'
    | 'expired';
export interface OidcView {
    readonly id: string;
    readonly status: OidcStatus;
    readonly ssh: boolean;
    readonly flow: string;
    readonly principal?: string;
    readonly choices?: readonly string[];
    readonly csrf?: string;
    readonly url?: string;
    readonly error?: string;
}
const token = (value: unknown): value is string =>
    typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(value);
const text = (value: unknown): value is string =>
    typeof value === 'string' && value.length <= 4096 && !/[\p{Cc}]/u.test(value);
const statuses: readonly string[] = [
    'created',
    'redirected',
    'exchanging',
    'approval',
    'authorizing',
    'accepted',
    'denied',
    'expired',
];

// Public error codes only. Never retain a provider response, query or error cause.
export class OidcError extends Error {
    constructor() {
        super('OIDC login unavailable');
    }
}

export async function oidcRequest(
    action: 'start' | 'callback' | 'status' | 'approve' | 'deny',
    fields: Record<string, string>,
    signal: AbortSignal,
): Promise<OidcView> {
    let response: Response;
    try {
        response = await fetch(`/api/v1/oidc/${action}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify(fields),
            credentials: 'same-origin',
            mode: 'same-origin',
            redirect: 'error',
            cache: 'no-store',
            referrerPolicy: 'no-referrer',
            signal: AbortSignal.any([signal, AbortSignal.timeout(20_000)]),
        });
    } catch {
        throw new OidcError();
    }
    if (!response.ok || !response.headers.get('Content-Type')?.startsWith('application/json')) {
        await response.body?.cancel().catch(() => undefined);
        throw new OidcError();
    }
    const reader = response.body?.getReader();
    if (!reader) {
        throw new OidcError();
    }
    const pieces: Uint8Array[] = [];
    let bytes = 0;
    try {
        while (true) {
            const next = await reader.read();
            if (next.done) {
                break;
            }
            bytes += next.value.byteLength;
            if (bytes > 16 << 10) {
                throw new OidcError();
            }
            pieces.push(next.value);
        }
    } catch {
        await reader.cancel().catch(() => undefined);
        throw new OidcError();
    } finally {
        reader.releaseLock();
    }
    const buffer = new Uint8Array(bytes);
    let position = 0;
    for (const piece of pieces) {
        buffer.set(piece, position);
        position += piece.length;
    }
    let raw: unknown;
    try {
        raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer));
    } catch {
        throw new OidcError();
    }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
        throw new OidcError();
    }
    const value = raw as Record<string, unknown>;
    if (
        Object.keys(value).some(
            (name) =>
                ![
                    'id',
                    'status',
                    'ssh',
                    'flow',
                    'principal',
                    'choices',
                    'csrf',
                    'url',
                    'error',
                ].includes(name),
        ) ||
        !token(value.id) ||
        !statuses.includes(value.status as string) ||
        typeof value.ssh !== 'boolean' ||
        !text(value.flow)
    ) {
        throw new OidcError();
    }
    for (const field of ['principal', 'error'] as const) {
        if (value[field] !== undefined && !text(value[field])) {
            throw new OidcError();
        }
    }
    if (value.url !== undefined) {
        if (!text(value.url)) {
            throw new OidcError();
        }
        let url: URL;
        try {
            url = new URL(value.url);
        } catch {
            throw new OidcError();
        }
        if (
            url.protocol !== 'https:' ||
            url.username ||
            url.password ||
            value.status !== 'redirected' ||
            !['start', 'status'].includes(action)
        ) {
            throw new OidcError();
        }
    }
    if (value.status === 'approval') {
        if (
            !value.ssh ||
            !text(value.principal) ||
            !token(value.csrf) ||
            !Array.isArray(value.choices) ||
            value.choices.length !== 3 ||
            new Set(value.choices).size !== 3 ||
            value.choices.some(
                (code: unknown) =>
                    typeof code !== 'string' || !/^[3479CDFHJKMNPRTUVWXY]{2}$/u.test(code),
            )
        ) {
            throw new OidcError();
        }
    } else if (value.choices !== undefined || value.csrf !== undefined) {
        throw new OidcError();
    }
    return value as unknown as OidcView;
}

export function oidcEntry(
    location: Pick<Location, 'pathname' | 'search' | 'hash'>,
): { action: 'start' | 'callback' | 'status'; fields: Record<string, string> } | null {
    if (
        location.pathname === '/login/callback' &&
        location.search.length <= 8193 &&
        location.hash === ''
    ) {
        return { action: 'callback', fields: { query: location.search.slice(1) } };
    }
    if (!['/login', '/login/'].includes(location.pathname) || location.search !== '') {
        return null;
    }
    const match = /^#(start|attempt)\/([A-Za-z0-9_-]{43})$/u.exec(location.hash);
    if (!match?.[1] || !match[2]) {
        return null;
    }
    return match[1] === 'start'
        ? { action: 'start', fields: { ticket: match[2] } }
        : { action: 'status', fields: { id: match[2] } };
}

export function oidcFinished(view: OidcView): boolean {
    return ['accepted', 'denied', 'expired'].includes(view.status);
}
