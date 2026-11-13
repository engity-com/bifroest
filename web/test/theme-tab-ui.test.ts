import { Tabs } from '@mui/material';
import { act, createElement, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { expect, it, vi } from 'vitest';
import type { WebAccess } from '../src/remember';
import { ConnectionTab } from '../src/terminal/ConnectionTab';
import { Menu } from '../src/ui/material';
import { preferredTheme, saveThemePreference, themePreferenceKey } from '../src/ui/preferences';
import { ThemeSwitcher } from '../src/ui/ThemeSwitcher';

function ThemeFixture() {
    const [scheme, setScheme] = useState(preferredTheme);
    return createElement(ThemeSwitcher, {
        scheme,
        onScheme: (next) => {
            if (next === 'auto' || next === 'light' || next === 'dark') {
                setScheme(next);
                saveThemePreference(next);
            }
        },
    });
}
it('cycles the always-visible theme control Auto → Light → Dark → Auto and saves only the origin preference', async () => {
    vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
    localStorage.removeItem(themePreferenceKey);
    const host = document.createElement('div');
    document.body.append(host);
    const root = createRoot(host);
    try {
        await act(async () => root.render(createElement(ThemeFixture)));
        for (const [from, to] of [
            ['Auto', 'Light'],
            ['Light', 'Dark'],
            ['Dark', 'Auto'],
        ] as const) {
            const button = host.querySelector<HTMLButtonElement>(
                `[aria-label="Appearance: ${from}"]`,
            );
            if (!button) {
                throw new Error('Missing visible theme control');
            }
            await act(async () => button.click());
            expect(localStorage.getItem(themePreferenceKey)).toBe(to.toLowerCase());
        }
    } finally {
        await act(async () => root.unmount());
        host.remove();
        localStorage.removeItem(themePreferenceKey);
        vi.unstubAllGlobals();
    }
});
it('uses the resolved flow title before terminal output, and middle-click closes without selecting a background tab', async () => {
    vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
    const host = document.createElement('div');
    document.body.append(host);
    const root = createRoot(host);
    const close = vi.fn();
    const select = vi.fn();
    const access = {
        status: () => 'active',
        subscribeStatus: () => () => {},
        snapshot: () => ({ flow: { name: 'docker', title: 'Development container' } }),
    } as unknown as WebAccess;
    const render = async (disabled = false) =>
        act(async () =>
            root.render(
                createElement(
                    Menu,
                    null,
                    createElement(
                        Tabs,
                        { value: false },
                        createElement(ConnectionTab, {
                            id: 1,
                            value: 1,
                            principal: 'blaubaer',
                            scope: 'docker',
                            kind: 'terminal',
                            access,
                            state: { phase: 'connected' },
                            active: false,
                            onSelect: select,
                            onMenu: vi.fn(),
                            onClose: close,
                            disabled,
                        }),
                    ),
                ),
            ),
        );
    try {
        await render();
        const tab = host.querySelector<HTMLElement>('[role="tab"]');
        if (!tab) {
            throw new Error('Missing tab');
        }
        expect(tab.textContent).toBe('Development container');
        expect(tab.getAttribute('aria-label')).toContain('blaubaer');
        const down = new MouseEvent('mousedown', { button: 1, bubbles: true, cancelable: true });
        await act(async () => {
            tab.dispatchEvent(down);
            tab.dispatchEvent(
                new MouseEvent('auxclick', { button: 1, bubbles: true, cancelable: true }),
            );
        });
        expect(down.defaultPrevented).toBe(true);
        expect(close).toHaveBeenCalledOnce();
        expect(select).not.toHaveBeenCalled();
        await render(true);
        await act(async () =>
            tab.dispatchEvent(new MouseEvent('auxclick', { button: 1, bubbles: true })),
        );
        expect(close).toHaveBeenCalledOnce();
    } finally {
        await act(async () => root.unmount());
        host.remove();
        vi.unstubAllGlobals();
    }
});
