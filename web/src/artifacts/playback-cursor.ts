import type { Terminal } from '@xterm/xterm';
import { EvidenceError } from './evidence-protocol';

// Xterm initializes its cursor on focus or buffer selection. Select the normal
// buffer of the NEW empty terminal and show its cursor, without focus or input.
// Finish before the
// playback scheduler owns reset/write ordering; later resets retain initialization.
export function initializePlaybackCursor(
    terminal: Pick<Terminal, 'write'>,
    signal: AbortSignal,
): Promise<void> {
    return new Promise((resolve, reject) => {
        let settled = false;
        const finish = (error?: EvidenceError) => {
            if (settled) {
                return;
            }
            settled = true;
            clearTimeout(timer);
            signal.removeEventListener('abort', aborted);
            if (error) {
                reject(error);
            } else {
                resolve();
            }
        };
        const aborted = () => finish(new EvidenceError('cancelled'));
        const timer = setTimeout(() => finish(new EvidenceError('unavailable')), 5000);
        signal.addEventListener('abort', aborted, { once: true });
        if (signal.aborted) {
            aborted();
            return;
        }
        let writing = true;
        let drained = false;
        try {
            terminal.write('\x1b[?47l\x1b[?25h', () => {
                if (writing) {
                    drained = true;
                } else {
                    finish();
                }
            });
            writing = false;
            if (drained) {
                finish();
            }
        } catch {
            finish(new EvidenceError('unavailable'));
        } finally {
            writing = false;
        }
    });
}
