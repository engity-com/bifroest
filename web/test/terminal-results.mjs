import assert from 'node:assert/strict';

// Observe only server frames from this page's terminal sockets. Opening frames
// and their bearer proofs are never inspected or retained.
export function observeTerminalResults(page) {
    const results = [];
    page.on('websocket', (socket) => {
        if (new URL(socket.url()).pathname !== '/api/v1/terminal') {
            return;
        }
        const chunks = [];
        const result = {
            socket,
            connection: null,
            status: null,
            error: null,
            closed: false,
            bytes: 0,
            text: () => Buffer.concat(chunks).toString('utf8'),
        };
        results.push(result);
        socket.on('framereceived', ({ payload }) => {
            if (typeof payload !== 'string') {
                if (payload.length < 2 || ![0, 1].includes(payload[0]) || result.status !== null) {
                    result.error = 'invalid or late terminal output';
                    return;
                }
                result.bytes += payload.length - 1;
                if (result.bytes > 1 << 20) {
                    result.error = 'fixture output exceeds the observation bound';
                    return;
                }
                chunks.push(Buffer.from(payload.subarray(1)));
                return;
            }
            try {
                const message = JSON.parse(payload);
                if (message.type === 'ready') {
                    result.connection = message.connectionId;
                } else if (message.type === 'exit') {
                    if (result.status !== null || !Number.isInteger(message.status)) {
                        result.error = 'invalid or duplicate terminal exit';
                    }
                    result.status = message.status;
                } else if (message.type === 'error') {
                    result.error = message.code;
                }
            } catch {
                result.error = 'malformed terminal control';
            }
        });
        socket.on('close', () => {
            result.closed = true;
        });
    });
    return { results, latest: () => results.at(-1) };
}

export async function expectTerminalExit(page, result, status, paneId) {
    assert(result, 'an explicitly started terminal socket must exist');
    if (!result.closed) {
        await result.socket.waitForEvent('close');
    }
    assert.equal(result.error, null);
    assert.match(result.connection, /^[1-9A-HJ-NP-Za-km-z]{16,22}$/u);
    assert.equal(result.status, status, 'the server must confirm the exact process exit');
    const selector = paneId ? `#${paneId}` : '[data-terminal-active="true"]';
    const pane = page.locator(selector);
    if (status === 0) {
        await pane.waitFor({ state: 'detached' });
    } else {
        await page.waitForFunction(
            ({ selector, status }) => {
                const pane = document.querySelector(selector);
                return (
                    pane?.getAttribute('data-terminal-ended') === 'true' &&
                    pane.getAttribute('data-terminal-exit-status') === String(status) &&
                    pane
                        .querySelector('.xterm-accessibility-tree')
                        ?.textContent?.includes(`Terminal ended with exit code: ${status}`)
                );
            },
            { selector, status },
        );
        assert.equal(await pane.locator('.terminal-state').count(), 0);
    }
    return result.text();
}
