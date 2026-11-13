// Test-only init script. Observe the original poll stream: no clone, read-ahead,
// replacement response, retry, body/header inspection or production hook.
export function installPollDiagnostics() {
    const events = [];
    let dropped = 0;
    let sequence = 0;
    const transport = globalThis.fetch.bind(globalThis);
    const record = (poll, event, eof, signal) => {
        if (events.length === 256) {
            dropped++;
            return;
        }
        events.push({
            poll,
            event,
            eof,
            aborted: signal?.aborted === true,
            at: Math.round(performance.now()),
        });
    };
    globalThis.bifroestPollDiagnostics = { events, dropped: () => dropped };
    globalThis.fetch = async (...args) => {
        const [input, options] = args;
        // Http.post supplies a URL and RequestInit; leave all other fetches alone.
        if (
            !(input instanceof URL) ||
            input.href !== new URL('/api/v1/login/poll', location.origin).href ||
            options?.method !== 'POST'
        ) {
            return transport(...args);
        }
        const poll = ++sequence;
        const signal = options.signal;
        let eof = false;
        record(poll, 'start', eof, signal);
        signal?.addEventListener('abort', () => record(poll, 'signal-abort', eof, signal), {
            once: true,
        });
        let response;
        try {
            response = await transport(...args);
        } catch (error) {
            record(poll, 'fetch-failed', eof, signal);
            throw error; // Preserve the original failure, never retain it in diagnostics.
        }
        record(poll, response.status === 200 ? 'headers-200' : 'headers-other', eof, signal);
        const body = response.body;
        if (body !== null) {
            const getReader = body.getReader.bind(body);
            const cancelBody = body.cancel.bind(body);
            body.cancel = (...arguments_) => {
                record(poll, 'body-cancel', eof, signal);
                return cancelBody(...arguments_);
            };
            body.getReader = (...arguments_) => {
                record(poll, 'get-reader', eof, signal);
                const reader = getReader(...arguments_);
                const read = reader.read.bind(reader);
                const cancel = reader.cancel.bind(reader);
                const release = reader.releaseLock.bind(reader);
                reader.read = async (...readArguments) => {
                    try {
                        const part = await read(...readArguments);
                        eof ||= part.done;
                        record(poll, part.done ? 'eof' : 'chunk', eof, signal);
                        return part;
                    } catch (error) {
                        record(poll, 'read-failed', eof, signal);
                        throw error;
                    }
                };
                reader.cancel = (...cancelArguments) => {
                    record(poll, 'reader-cancel', eof, signal);
                    return cancel(...cancelArguments);
                };
                reader.releaseLock = () => {
                    record(poll, 'release-lock', eof, signal);
                    return release();
                };
                return reader;
            };
        }
        return response;
    };
}

export async function pollDiagnostics(page) {
    try {
        return await page.evaluate(() => {
            const diagnostics = globalThis.bifroestPollDiagnostics;
            return diagnostics
                ? { events: diagnostics.events, dropped: diagnostics.dropped() }
                : null;
        });
    } catch {
        return { unavailable: true }; // No arbitrary exception/cause/closed-page text.
    }
}
