import { Tabs } from '@mui/material';
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { expect, it, vi } from 'vitest';
import { page, userEvent } from 'vitest/browser';
import { WebAccess } from '../src/remember/client';
import { Http } from '../src/remember/http';
import { ConnectionTab } from '../src/terminal/ConnectionTab';
import { Menu } from '../src/ui/material';
import type { WorkspaceTab } from '../src/workspace/model';
import { useTabLayout } from '../src/workspace/use-tab-layout';
import { required } from './required';
import '../src/ui/app.css';

function TabLayoutFixture({
    tabs,
    active,
    onSelect,
}: {
    tabs: WorkspaceTab[];
    active: number;
    onSelect: (id: number) => void;
}) {
    const list = useTabLayout();
    return createElement(
        Menu,
        null,
        createElement(
            'div',
            { className: 'application-tabs' },
            createElement(
                Tabs,
                {
                    ref: list,
                    className: 'terminal-tab-list',
                    value: active,
                    variant: 'scrollable',
                    scrollButtons: 'auto',
                    allowScrollButtonsMobile: true,
                    selectionFollowsFocus: true,
                    onChange: (event, id: number) => {
                        if (event.type !== 'click') {
                            onSelect(id);
                        }
                    },
                },
                ...tabs.map((tab) =>
                    createElement(ConnectionTab, {
                        key: tab.id,
                        id: tab.id,
                        value: tab.id,
                        access: tab.access,
                        principal: `user-${tab.id}`,
                        scope: tab.scope.slug,
                        kind: tab.kind,
                        state: tab.state,
                        title: tab.title ?? '',
                        active: active === tab.id,
                        onSelect: () => onSelect(tab.id),
                        onMenu: () => {},
                        onClose: () => {},
                    }),
                ),
            ),
            createElement('button', { type: 'button', style: { width: 68, flexShrink: 0 } }, 'New'),
            createElement('div', { className: 'workspace-utilities', style: { width: 80 } }),
        ),
    );
}

it('does not snap the tab strip back to the active terminal when a background title changes', async () => {
    vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
    await page.viewport(390, 844);
    const host = document.createElement('div');
    host.className = 'application-bar';
    document.body.append(host);
    const root = createRoot(host);
    let active = 3;
    let tabs: WorkspaceTab[] = [1, 2, 3].map((id) => {
        const scope = { origin: 'https://app.example.org', slug: 'Work' };
        const access = new WebAccess(
            new Http(scope),
            {
                scope,
                principal: `user-${id}`,
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
                accessToken: `bwa1.${'A'.repeat(43)}`,
                environment: 'terminal',
                terminalAvailable: true,
            },
            null,
        );
        return {
            id,
            scope,
            access,
            signal: new AbortController().signal,
            kind: 'terminal',
            state: { phase: 'connected' },
            inputClosed: false,
            title: 'untrusted-backend-title',
        };
    });
    const render = () =>
        root.render(
            createElement(TabLayoutFixture, {
                tabs,
                active,
                onSelect: (id) => {
                    active = id;
                    render();
                },
            }),
        );
    try {
        await act(async () => render());
        const scroller = required(host.querySelector<HTMLElement>('.MuiTabs-scroller'));
        await expect.poll(() => host.querySelectorAll('.MuiTabs-scrollButtons').length).toBe(2);
        await expect
            .poll(() => {
                const tab = required(host.querySelector('#terminal-tab-3')).getBoundingClientRect();
                return (
                    tab.width <= scroller.getBoundingClientRect().width + 1 &&
                    scroller.scrollLeft === scroller.scrollWidth - scroller.clientWidth
                );
            })
            .toBe(true);
        // Browsing other tabs must not select them or get undone by terminal events.
        const start = scroller.scrollLeft;
        await act(async () =>
            userEvent.click(required(host.querySelector<HTMLElement>('.MuiTabs-scrollButtons'))),
        );
        await expect.poll(() => scroller.scrollLeft).toBe(start - scroller.clientWidth);
        await act(async () =>
            userEvent.click(required(host.querySelector<HTMLElement>('.MuiTabs-scrollButtons'))),
        );
        await expect.poll(() => scroller.scrollLeft).toBe(0);
        tabs = tabs.map((tab) => (tab.id === 2 ? { ...tab, title: 'updated-backend-title' } : tab));
        await act(async () => render());
        expect(scroller.scrollLeft).toBe(0);
        await act(async () =>
            userEvent.click(page.getByRole('tab', { name: 'Terminal 1 user-1', exact: true })),
        );
        expect(active).toBe(1);
        await act(async () => userEvent.keyboard('{ArrowRight}{ArrowRight}'));
        expect(active).toBe(3);
        await page.viewport(320, 844);
        await expect
            .poll(() => {
                const tab = required(host.querySelector('#terminal-tab-3')).getBoundingClientRect();
                const viewport = scroller.getBoundingClientRect();
                return tab.left >= viewport.left - 1 && tab.right <= viewport.right + 1;
            })
            .toBe(true);
    } finally {
        await act(async () => root.unmount());
        host.remove();
        await page.viewport(1280, 720);
        vi.unstubAllGlobals();
    }
});
