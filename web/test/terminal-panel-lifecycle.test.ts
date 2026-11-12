import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { WebAccess } from '../src/remember';
import type { TerminalState } from '../src/terminal/socket';
import { TerminalPanel } from '../src/terminal/TerminalPanel';
import { profilePreferencesResetEvent } from '../src/ui/profile-reset';
import { adjustTerminalFontSize, terminalFontPreferenceKey } from '../src/ui/terminal-font';

const owned = vi.hoisted(() => ({
    terminals: [] as { options: Record<string, unknown>; writes: string[] }[],
    states: [] as ((state: TerminalState) => void)[],
}));
vi.mock('@xterm/xterm', () => ({
    Terminal: class {
        options: Record<string, unknown>;
        writes: string[] = [];
        cols = 80;
        rows = 24;
        parser = { registerOscHandler: () => ({ dispose() {} }) };
        constructor(options: Record<string, unknown>) {
            this.options = options;
            owned.terminals.push(this);
        }
        open(element: HTMLElement) {
            element.append(document.createElement('textarea'));
        }
        loadAddon() {}
        attachCustomKeyEventHandler() {}
        onTitleChange() {
            return { dispose() {} };
        }
        onData() {
            return { dispose() {} };
        }
        onBinary() {
            return { dispose() {} };
        }
        focus() {}
        dispose() {}
        write(value: string | Uint8Array, done?: () => void) {
            this.writes.push(typeof value === 'string' ? value : new TextDecoder().decode(value));
            done?.();
        }
    },
}));
vi.mock('@xterm/addon-fit', () => ({
    FitAddon: class {
        fit() {}
    },
}));
vi.mock('../src/terminal/renderer', () => ({ installTerminalRenderer: () => ({ dispose() {} }) }));
vi.mock('../src/terminal/socket', () => ({
    TerminalConnection: class {
        constructor(
            _access: unknown,
            _request: unknown,
            _renderer: unknown,
            state: (value: TerminalState) => void,
        ) {
            owned.states.push(state);
            state({ phase: 'connected' });
        }
        dispose() {}
        resize() {}
        input() {}
        keepAliveSettings() {
            return { locked: true, interval: '30s' };
        }
        setKeepAlive() {}
        disconnect() {}
        eof() {
            return true;
        }
        signal() {
            return true;
        }
    },
}));
const cleanups: (() => void)[] = [];
beforeEach(() => {
    vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
    const nonce = document.createElement('meta');
    nonce.name = 'bifroest-nonce';
    nonce.content = `${'A'.repeat(43)}=`;
    document.head.append(nonce);
    cleanups.push(() => nonce.remove());
    owned.terminals.length = 0;
    owned.states.length = 0;
});
afterEach(async () => {
    await act(async () => {
        for (const cleanup of cleanups.splice(0)) {
            cleanup();
        }
    });
    localStorage.removeItem(terminalFontPreferenceKey);
    vi.unstubAllGlobals();
});
async function mount(id: number) {
    const host = document.createElement('div');
    document.body.append(host);
    const root = createRoot(host);
    cleanups.push(() => {
        root.unmount();
        host.remove();
    });
    const access = {
        snapshot: () => ({ scope: { origin: 'https://app.example.org', slug: 'Work' } }),
        registerResetCleanup: () => () => {},
    } as unknown as WebAccess;
    await act(async () =>
        root.render(
            createElement(TerminalPanel, {
                id,
                access,
                signal: new AbortController().signal,
                active: true,
                inputAllowed: true,
                focusOnActivate: false,
                onState: vi.fn(),
                onActions: vi.fn(),
            }),
        ),
    );
    await vi.waitFor(() => expect(owned.states).toHaveLength(id));
    return host;
}
it('appends a nonzero exit exactly once inside xterm, never as recorded/server output or a separate status block', async () => {
    const host = await mount(1);
    await act(async () => {
        owned.states[0]?.({ phase: 'exited', status: 7 });
        owned.states[0]?.({ phase: 'exited', status: 7 });
    });
    expect(
        owned.terminals[0]?.writes.filter((value) =>
            value.includes('Terminal ended with exit code:'),
        ),
    ).toEqual(['\r\nTerminal ended with exit code: 7\r\n']);
    expect(host.querySelector('.terminal-state')).toBeNull();
});
it('does not append a success message and updates every mounted terminal without creating new connections', async () => {
    await mount(1);
    await mount(2);
    const before = owned.terminals[0]?.options.fontSize;
    await act(async () => {
        adjustTerminalFontSize(1);
    });
    expect(owned.terminals[0]?.options.fontSize).toBe(Number(before) + 1);
    expect(owned.terminals[1]?.options.fontSize).toBe(Number(before) + 1);
    expect(owned.states).toHaveLength(2);
    await act(async () => {
        localStorage.setItem(terminalFontPreferenceKey, '18');
        window.dispatchEvent(
            new StorageEvent('storage', { key: terminalFontPreferenceKey, newValue: '18' }),
        );
    });
    expect(owned.terminals.map((terminal) => terminal.options.fontSize)).toEqual([18, 18]);
    await act(async () => {
        localStorage.removeItem(terminalFontPreferenceKey);
        window.dispatchEvent(new Event(profilePreferencesResetEvent));
    });
    expect(owned.terminals.map((terminal) => terminal.options.fontSize)).toEqual([14, 14]);
    await act(async () => owned.states[0]?.({ phase: 'exited', status: 0 }));
    expect(owned.terminals[0]?.writes.join('')).not.toContain('Terminal ended');
});
