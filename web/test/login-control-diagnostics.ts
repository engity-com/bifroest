import type { Page } from './fixture-types.ts';

export interface LoginControlDiagnostics {
    events: {
        action: 'poll' | 'reply';
        sequence: number;
        event: string;
        eof: boolean;
        aborted: boolean;
        at: number;
        status?: number;
    }[];
    dropped(): number;
}

// Test-only init script. Observe the original login-control streams: no clone,
// read-ahead, replacement response, retry, payload inspection or production hook.
export function installLoginControlDiagnostics() {
    const events: LoginControlDiagnostics['events'] = [];
    let dropped = 0;
    const sequences = { poll: 0, reply: 0 };
    const transport = globalThis.fetch.bind(globalThis);
    const record = (
        action: 'poll' | 'reply',
        sequence: number,
        event: string,
        eof: boolean,
        signal: AbortSignal | null | undefined,
        status?: number,
    ) => {
        if (events.length === 256) {
            dropped++;
            return;
        }
        events.push({
            action,
            sequence,
            event,
            eof,
            aborted: signal?.aborted === true,
            at: Math.round(performance.timeOrigin + performance.now()),
            ...(status === undefined ? {} : { status }),
        });
    };
    globalThis.bifroestLoginControlDiagnostics = { events, dropped: () => dropped };
    globalThis.fetch = async (...args) => {
        const [input, options] = args;
        // Http.post supplies a URL and RequestInit; leave all other fetches alone.
        if (!(input instanceof URL) || options?.method !== 'POST') {
            return transport(...args);
        }
        const action =
            input.href === new URL('/api/v1/login/poll', location.origin).href
                ? 'poll'
                : input.href === new URL('/api/v1/login/reply', location.origin).href
                  ? 'reply'
                  : null;
        if (action === null) {
            return transport(...args);
        }
        const sequence = ++sequences[action];
        const signal = options.signal;
        let eof = false;
        record(action, sequence, 'start', eof, signal);
        signal?.addEventListener(
            'abort',
            () => record(action, sequence, 'signal-abort', eof, signal),
            { once: true },
        );
        let response: Response;
        try {
            response = await transport(...args);
        } catch (error) {
            record(action, sequence, 'fetch-failed', eof, signal);
            throw error; // Preserve the original failure, never retain it in diagnostics.
        }
        record(action, sequence, 'headers', eof, signal, response.status);
        const body = response.body;
        if (body !== null) {
            const getReader = body.getReader.bind(body);
            const cancelBody = body.cancel.bind(body);
            body.cancel = (...arguments_) => {
                record(action, sequence, 'body-cancel', eof, signal);
                return cancelBody(...arguments_);
            };
            body.getReader = ((...arguments_: Parameters<typeof body.getReader>) => {
                record(action, sequence, 'get-reader', eof, signal);
                const reader = getReader(...arguments_) as ReadableStreamDefaultReader<Uint8Array>;
                const read = reader.read.bind(reader);
                const cancel = reader.cancel.bind(reader);
                const release = reader.releaseLock.bind(reader);
                reader.read = async (...readArguments: Parameters<typeof read>) => {
                    try {
                        const part = await read(...readArguments);
                        eof ||= part.done === true;
                        record(action, sequence, part.done ? 'eof' : 'chunk', eof, signal);
                        return part;
                    } catch (error) {
                        record(action, sequence, 'read-failed', eof, signal);
                        throw error;
                    }
                };
                reader.cancel = (...cancelArguments) => {
                    record(action, sequence, 'reader-cancel', eof, signal);
                    return cancel(...cancelArguments);
                };
                reader.releaseLock = () => {
                    record(action, sequence, 'release-lock', eof, signal);
                    return release();
                };
                return reader;
            }) as typeof body.getReader;
        }
        return response;
    };
}

export async function loginControlDiagnostics(page: Pick<Page, 'evaluate'>) {
    try {
        return await page.evaluate(() => {
            const diagnostics = globalThis.bifroestLoginControlDiagnostics;
            return diagnostics
                ? {
                      events: diagnostics.events,
                      dropped: diagnostics.dropped(),
                      timeOrigin: performance.timeOrigin,
                  }
                : null;
        });
    } catch {
        return { unavailable: true }; // No arbitrary exception/cause/closed-page text.
    }
}
