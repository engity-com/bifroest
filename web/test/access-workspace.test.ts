import { act, type ComponentProps, createElement, StrictMode, useCallback, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SessionActionConfirmation } from '../src/management/action';
import type { ManagementConnection } from '../src/management/channel';
import { m } from '../src/management/messages';
import { BrowserBinding, BrowserClient } from '../src/remember';
import { WebAccess } from '../src/remember/client';
import { Http } from '../src/remember/http';
import type { TerminalState } from '../src/terminal/socket';
import { accessMessages } from '../src/ui/access-messages';
import { t } from '../src/ui/messages';
import { ConnectionWorkspace } from '../src/workspace/ConnectionWorkspace';
import type { ConnectionView, WorkspaceControls } from '../src/workspace/model';
import { required } from './required';
import { openSessionTarget, sessionTargetAction } from './session-target-ui';

const panels = vi.hoisted(() => ({
    terminals: new Map<number, AbortSignal>(),
    unmounted: [] as number[],
    artifactsMounted: [] as WebAccess[],
    states: new Map<number, (state: TerminalState) => void>(),
    starts: [] as number[],
}));
vi.mock('../src/terminal/TerminalPanel', async () => {
    const { createElement, useEffect } = await import('react');
    return {
        terminalStatus: () => 'terminalConnected',
        TerminalPanel: ({
            id,
            signal,
            onState,
        }: {
            id: number;
            signal: AbortSignal;
            onState: (id: number, state: TerminalState) => void;
        }) => {
            useEffect(() => {
                panels.terminals.set(id, signal);
                panels.states.set(id, (state) => onState(id, state));
                if (!signal.aborted) {
                    panels.starts.push(id);
                    onState(id, { phase: 'connected' });
                }
                return () => {
                    panels.unmounted.push(id);
                };
            }, [id, signal, onState]);
            return createElement('span', null, `Running terminal ${id}`);
        },
    };
});
vi.mock('../src/artifacts/ArtifactPanel', async () => {
    const { createElement, useEffect, useState } = await import('react');
    return {
        ArtifactPanel: ({
            access,
            disabled,
            remoteDisabled,
        }: {
            access: WebAccess;
            disabled: boolean;
            remoteDisabled?: boolean;
        }) => {
            const [loaded, setLoaded] = useState(false);
            useEffect(() => {
                panels.artifactsMounted.push(access);
            }, [access]);
            useEffect(() => {
                if (disabled) {
                    setLoaded(false);
                }
            }, [disabled]);
            return createElement(
                'section',
                null,
                createElement(
                    'button',
                    { disabled: disabled || remoteDisabled },
                    'Fixture server load',
                ),
                createElement(
                    'button',
                    { disabled, onClick: () => setLoaded(true) },
                    'Fixture local recording',
                ),
                loaded ? createElement('output', null, 'Retained local recording') : null,
            );
        },
    };
});

// Warm the lazy management view before starting the deliberately real deadline.
await import('../src/management/ManagementPanel');
const cleanups: (() => void)[] = [];
beforeEach(() => {
    vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
    vi.stubGlobal(
        'fetch',
        vi.fn(async () => {
            throw new Error('Unexpected network access');
        }),
    );
    vi.spyOn(BrowserBinding, 'load');
    vi.spyOn(BrowserClient.prototype, 'resume');
    // These are standalone-grant expiry/retention tests, deliberately WITHOUT
    // admitting a live channel. Admitted post-expiry behavior is covered by the
    // real socket and browser management-channel regressions.
    vi.spyOn(WebAccess.prototype, 'openManagement').mockReturnValue({
        disconnect() {},
    } as ManagementConnection);
    panels.terminals.clear();
    panels.unmounted.length = 0;
    panels.artifactsMounted.length = 0;
    panels.states.clear();
    panels.starts.length = 0;
});
afterEach(async () => {
    await act(async () => {
        for (const cleanup of cleanups.splice(0).reverse()) {
            cleanup();
        }
    });
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
});

function json(value: unknown, status = 200) {
    return new Response(JSON.stringify(value), {
        status,
        headers: { 'Content-Type': 'application/json' },
    });
}
function permission(slug: string, lifetime = 60_000, terminal = false) {
    const scope = { origin: 'https://app.example.org', slug };
    const expiresAt = new Date(Date.now() + lifetime).toISOString();
    const transport = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = new URL(String(input)).pathname;
        if (path.endsWith('/management/version/show')) {
            const fields = JSON.parse(String(init?.body)) as Record<string, string>;
            return json({
                version: 1,
                operation: 'version.show',
                versionInfo: {
                    detail: fields.long === 'true' ? 'long' : 'short',
                    text: 'Owned version',
                },
            });
        }
        for (const kind of ['sessions', 'flows']) {
            if (path.endsWith(`/management/${kind}/list`)) {
                return json({
                    version: 1,
                    operation: `${kind}.list`,
                    [kind]: { items: [], next: '', skipped: 0 },
                });
            }
        }
        return new Response(null, { status: 503 });
    });
    return {
        transport,
        access: new WebAccess(
            new Http(scope, transport),
            {
                scope,
                principal: slug,
                expiresAt,
                accessToken: `bwa1.${'A'.repeat(43)}`,
                environment: terminal ? 'terminal' : 'management',
                terminalAvailable: terminal,
            },
            null,
        ),
    };
}

function Harness(
    props: Omit<ComponentProps<typeof ConnectionWorkspace>, 'activeView' | 'onSelectView'>,
) {
    const [active, setActive] = useState<number | null>(null);
    const select = useCallback((view: ConnectionView | null) => setActive(view?.id ?? null), []);
    return createElement(ConnectionWorkspace, {
        ...props,
        activeView: active,
        onSelectView: select,
    });
}

async function mountWorkspace(initial: WebAccess) {
    const onSignIn = vi.fn();
    const onViewsChange = vi.fn();
    const onActionLock = vi.fn();
    const container = document.createElement('div');
    document.body.append(container);
    const root = createRoot(container);
    cleanups.push(() => {
        root.unmount();
        container.remove();
    });
    let options = { authorizationEvent: initial, blocked: false, focusBlocked: false };
    const callbacks = {
        authentication: null,
        retiredAccess: null,
        unavailableAccess: null,
        title: 'Access lifetime workspace',
        utilities: null,
        notice: null,
        onSignIn,
        onNewConnection: vi.fn(),
        onViewsChange,
        onActionLock,
        onTabCount: vi.fn(),
        onLogout: vi.fn(),
    };
    const render = async (next: Partial<typeof options> = {}) => {
        options = { ...options, ...next };
        await act(async () => root.render(createElement(Harness, { ...callbacks, ...options })));
    };
    await render();
    await vi.waitFor(async () => {
        await act(async () => {});
        expect(container.querySelector('.admin-shell')).not.toBeNull();
        expect(button('Fixture local recording', container)).toBeDefined();
    });
    return { container, render, onSignIn, onViewsChange, onActionLock };
}
function button(name: string, parent: ParentNode = document): HTMLButtonElement {
    return required(
        [...parent.querySelectorAll<HTMLButtonElement>('button,a[href]')].find(
            (node) => node.textContent === name,
        ),
    );
}
async function click(element: HTMLElement | null) {
    await act(async () => required(element).click());
}
async function fill(label: string, value: string) {
    const field = required(
        [...document.querySelectorAll<HTMLInputElement>('input')].find(
            (node) => node.labels?.[0]?.textContent?.replace(/\s*\*$/, '') === label,
        ),
    );
    await act(async () => {
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(
            field,
            value,
        );
        field.dispatchEvent(new Event('input', { bubbles: true }));
    });
}
async function expired(access: WebAccess) {
    await vi.waitFor(
        async () => {
            await act(async () => {});
            expect(access.status()).toBe('expired');
            expect(document.querySelector('[data-access-status="expired"]')).not.toBeNull();
        },
        { timeout: 4_000 },
    );
}
function noAuthenticationOrSavedReads() {
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(BrowserBinding.load).not.toHaveBeenCalled();
    expect(BrowserClient.prototype.resume).not.toHaveBeenCalled();
}

async function mountTerminals(strict = false) {
    const container = document.createElement('div');
    document.body.append(container);
    const root = createRoot(container);
    cleanups.push(() => {
        root.unmount();
        container.remove();
    });
    const callbacks = {
        onSignIn: vi.fn(),
        onNewConnection: vi.fn(),
        onViewsChange: vi.fn(),
        onActionLock: vi.fn(),
        onTabCount: vi.fn(),
        onLogout: vi.fn(),
        onWorkspaceControls: vi.fn<(controls: WorkspaceControls | null) => void>(),
    };
    let options: Omit<ComponentProps<typeof ConnectionWorkspace>, 'activeView' | 'onSelectView'> = {
        ...callbacks,
        authorizationEvent: null,
        authentication: null,
        retiredAccess: null,
        unavailableAccess: null,
        blocked: false,
        focusBlocked: false,
        title: 'Workspace lifecycle',
        notice: null,
        utilities: null,
    };
    const render = async (change: Partial<typeof options> = {}) => {
        options = { ...options, ...change };
        await act(async () => {
            const content = createElement(Harness, options);
            root.render(strict ? createElement(StrictMode, null, content) : content);
        });
    };
    await render();
    return { container, render, callbacks };
}

describe('workspace model React adapter', () => {
    it('keeps terminal callback identities and owned connections stable across parent updates and tab switches', async () => {
        const w = await mountTerminals();
        const first = permission('First', 60_000, true);
        const second = permission('Second', 60_000, true);
        await w.render({ authorizationEvent: first.access });
        await w.render({ authorizationEvent: second.access });
        const before = [...panels.terminals.values()];
        await w.render({ onViewsChange: vi.fn(), onTabCount: vi.fn(), title: 'Changed title' });
        await click(document.getElementById('terminal-tab-1'));
        await click(document.getElementById('terminal-tab-2'));
        expect(panels.starts).toEqual([1, 2]);
        expect(panels.unmounted).toEqual([]);
        expect(before.every((signal) => !signal.aborted)).toBe(true);
        expect(first.transport).not.toHaveBeenCalled();
        expect(second.transport).not.toHaveBeenCalled();
        noAuthenticationOrSavedReads();
    });

    it('retains nonzero output, removes only the zero-exit tab and reports the last tab closed', async () => {
        const w = await mountTerminals();
        await w.render({ authorizationEvent: permission('First', 60_000, true).access });
        await w.render({ authorizationEvent: permission('Second', 60_000, true).access });
        await act(async () => required(panels.states.get(1))({ phase: 'exited', status: 7 }));
        expect(document.getElementById('terminal-pane-1')?.dataset.terminalExitStatus).toBe('7');
        expect(panels.terminals.get(1)?.aborted).toBe(false);
        await act(async () => required(panels.states.get(2))({ phase: 'exited', status: 0 }));
        expect(document.getElementById('terminal-tab-2')).toBeNull();
        expect(document.getElementById('terminal-tab-1')?.getAttribute('aria-selected')).toBe(
            'true',
        );
        expect(w.callbacks.onTabCount).toHaveBeenLastCalledWith(1);
        await click(
            required(
                document.querySelector<HTMLElement>(`[aria-label="${t('terminalCloseTab')} 1"]`),
            ),
        );
        expect(document.getElementById('terminal-tab-1')).toBeNull();
        expect(w.callbacks.onTabCount).toHaveBeenLastCalledWith(0);
    });

    it('exposes stable close-all controls that consult the latest committed guard', async () => {
        const w = await mountTerminals();
        await w.render({ authorizationEvent: permission('First', 60_000, true).access });
        const controls = required(w.callbacks.onWorkspaceControls.mock.calls.at(-1)?.[0]);
        await w.render({ blocked: true });
        expect(controls.closeAll()).toBe(false);
        expect(panels.terminals.get(1)?.aborted).toBe(false);
        await act(async () => {
            expect(controls.closeAll({ resetConfirmed: true })).toBe(true);
        });
        expect(panels.terminals.get(1)?.aborted).toBe(true);
        expect(w.callbacks.onTabCount).toHaveBeenLastCalledWith(0);
        expect(w.callbacks.onWorkspaceControls).toHaveBeenCalledTimes(1);
        await w.render({ blocked: false });
        expect(document.getElementById('terminal-tab-2')).toBeNull();
        noAuthenticationOrSavedReads();
    });

    it('accepts an explicit grant exactly once after StrictMode effect replay', async () => {
        const w = await mountTerminals(true);
        const owner = permission('Strict', 60_000, true);
        await w.render({ authorizationEvent: owner.access });
        await w.render();
        expect(document.querySelectorAll('[role="tab"]')).toHaveLength(1);
        expect(w.callbacks.onViewsChange).toHaveBeenCalledTimes(1);
        expect(owner.transport).not.toHaveBeenCalled();
        noAuthenticationOrSavedReads();
    });

    it('keeps authentication in the Material tab selection contract without retiring a running shell', async () => {
        const w = await mountTerminals();
        const owner = permission('Login', 60_000, true);
        await w.render({ authorizationEvent: owner.access });
        const onCancel = vi.fn();
        await w.render({
            authentication: {
                id: 10,
                scope: owner.access.snapshot().scope,
                user: 'Next login',
                step: null,
                pending: true,
                remembering: false,
                message: null,
                provider: null,
                onAnswer: vi.fn(),
                onCancel,
            },
        });
        expect(document.getElementById('authentication-tab')?.getAttribute('aria-selected')).toBe(
            'true',
        );
        expect(document.getElementById('terminal-pane-1')?.hidden).toBe(true);
        expect(panels.terminals.get(1)?.aborted).toBe(false);
        expect(w.callbacks.onTabCount).toHaveBeenLastCalledWith(2);
        await click(
            required(
                document.querySelector<HTMLElement>(`[aria-label="${t('cancelAuthentication')}"]`),
            ),
        );
        expect(onCancel).toHaveBeenCalledTimes(1);
        await w.render({ authentication: null });
        expect(document.getElementById('terminal-tab-1')?.getAttribute('aria-selected')).toBe(
            'true',
        );
        expect(panels.starts).toEqual([1]);
        noAuthenticationOrSavedReads();
    });

    it('cycles tabs with the keyboard adapter but never through a foreign focus lock', async () => {
        const w = await mountTerminals();
        await w.render({ authorizationEvent: permission('First', 60_000, true).access });
        await w.render({ authorizationEvent: permission('Second', 60_000, true).access });
        const cycle = async () =>
            act(async () => {
                window.dispatchEvent(
                    new KeyboardEvent('keydown', {
                        key: 'Tab',
                        ctrlKey: true,
                        bubbles: true,
                        cancelable: true,
                    }),
                );
            });
        await cycle();
        expect(document.getElementById('terminal-tab-1')?.getAttribute('aria-selected')).toBe(
            'true',
        );
        await w.render({ focusBlocked: true });
        await cycle();
        expect(document.getElementById('terminal-tab-1')?.getAttribute('aria-selected')).toBe(
            'true',
        );
        await w.render({ focusBlocked: false });
        await cycle();
        expect(document.getElementById('terminal-tab-2')?.getAttribute('aria-selected')).toBe(
            'true',
        );
        expect(panels.starts).toEqual([1, 2]);
    });
});

describe('standalone management grant expiry without an admitted channel', () => {
    it('requires explicit authentication rather than opening another management view on the same channel owner', async () => {
        const owner = permission('Original');
        const workspace = await mountWorkspace(owner.access);
        const tab = required(document.getElementById('terminal-tab-1'));
        await act(async () => {
            tab.dispatchEvent(
                new MouseEvent('contextmenu', {
                    bubbles: true,
                    cancelable: true,
                    clientX: 20,
                    clientY: 20,
                }),
            );
        });
        await vi.waitFor(() =>
            expect(
                [...document.querySelectorAll('[role="menuitem"]')].some(
                    (node) => node.textContent === t('connectionDuplicate'),
                ),
            ).toBe(true),
        );
        await click(
            required(
                [...document.querySelectorAll<HTMLElement>('[role="menuitem"]')].find(
                    (node) => node.textContent === t('connectionDuplicate'),
                ),
            ),
        );
        expect(workspace.onSignIn).toHaveBeenCalledExactlyOnceWith(owner.access.snapshot().scope);
        expect(document.getElementById('terminal-tab-2')).toBeNull();
        expect(WebAccess.prototype.openManagement).toHaveBeenCalledTimes(1);
        expect(panels.artifactsMounted).toEqual([owner.access]);
    });
    it('expires on the real clock, preserves local evidence and requests only an explicit new sign-in in its own scope', async () => {
        const owner = permission('Original', 1_500);
        const workspace = await mountWorkspace(owner.access);
        const tab = required(document.getElementById('terminal-tab-1'));
        expect(tab.dataset.accessStatus).toBe('active');
        const activeColor = getComputedStyle(
            required(tab.querySelector('[data-testid="CircleIcon"]')),
        ).color;
        await click(button(t('workspaceVersion')));
        await vi.waitFor(() => expect(workspace.container.textContent).toContain('Owned version'));
        await vi.waitFor(() =>
            expect(
                owner.transport.mock.calls.filter(([path]) =>
                    String(path).endsWith('/management/version/show'),
                ),
            ).toHaveLength(2),
        );
        const reads = owner.transport.mock.calls.length;
        await click(button(t('workspaceAuditlogs')));
        await click(button('Fixture local recording'));
        expect(workspace.container.textContent).toContain('Retained local recording');
        await expired(owner.access);
        expect(Date.now()).toBeGreaterThanOrEqual(Date.parse(owner.access.snapshot().expiresAt));
        expect(tab.textContent).toContain(accessMessages.expired);
        expect(
            getComputedStyle(required(tab.querySelector('[data-testid="CircleIcon"]'))).color,
        ).not.toBe(activeColor);
        expect(tab.getAttribute('aria-label')).toContain(accessMessages.reauthenticate);
        expect(button(m('versionRefresh')).disabled).toBe(true);
        expect(button('Fixture server load').disabled).toBe(true);
        expect(button('Fixture local recording').disabled).toBe(false);
        expect(workspace.container.textContent).toContain(accessMessages.expiredNotice);
        expect(workspace.container.textContent).toContain('Retained local recording');
        expect(panels.artifactsMounted).toEqual([owner.access]);
        expect(owner.transport).toHaveBeenCalledTimes(reads);
        expect(workspace.onSignIn).not.toHaveBeenCalled();
        noAuthenticationOrSavedReads();
        await click(button(accessMessages.reauthenticate));
        expect(workspace.onSignIn).toHaveBeenCalledExactlyOnceWith(owner.access.snapshot().scope);
        expect(workspace.onViewsChange).toHaveBeenLastCalledWith([
            expect.objectContaining({ access: owner.access }),
        ]);
        expect(owner.transport).toHaveBeenCalledTimes(reads);
    });

    it('allows returning to an expired background tab without reads, remounts or disturbing a running terminal', async () => {
        const owner = permission('Original', 1_200);
        const workspace = await mountWorkspace(owner.access);
        await click(button(t('workspaceAuditlogs')));
        await click(button('Fixture local recording'));
        const reads = owner.transport.mock.calls.length;
        const shell = permission('Shell', 60_000, true);
        await workspace.render({ authorizationEvent: shell.access });
        await expired(owner.access);
        expect(panels.terminals.get(2)?.aborted).toBe(false);
        expect(panels.unmounted).toEqual([]);
        await click(document.getElementById('terminal-tab-1'));
        expect(document.getElementById('terminal-pane-1')?.dataset.connectionActive).toBe('true');
        expect(workspace.container.textContent).toContain('Retained local recording');
        expect(panels.artifactsMounted).toEqual([owner.access]);
        expect(panels.terminals.get(2)?.aborted).toBe(false);
        expect(panels.unmounted).toEqual([]);
        expect(owner.transport).toHaveBeenCalledTimes(reads);
        expect(shell.transport).not.toHaveBeenCalled();
        expect(workspace.onSignIn).not.toHaveBeenCalled();
        noAuthenticationOrSavedReads();
        await click(button(accessMessages.reauthenticate));
        expect(workspace.onSignIn).toHaveBeenCalledExactlyOnceWith(owner.access.snapshot().scope);
    });

    it.each(['blocked', 'focusBlocked'] as const)(
        'does not offer a seemingly active reauthentication while %s',
        async (guard) => {
            const owner = permission('Original', -1);
            const workspace = await mountWorkspace(owner.access);
            await workspace.render({ [guard]: true });
            expect(button(accessMessages.reauthenticate).disabled).toBe(true);
            await click(button(accessMessages.reauthenticate));
            expect(workspace.onSignIn).not.toHaveBeenCalled();
            await workspace.render({ [guard]: false });
            expect(button(accessMessages.reauthenticate).disabled).toBe(false);
            expect(owner.transport).not.toHaveBeenCalled();
            noAuthenticationOrSavedReads();
        },
    );

    it('keeps reauthentication blocked across expiry while an action outcome is unknown, until explicit dismissal', async () => {
        const owner = permission('Original', 1_800);
        const target = { flow: 'worker', id: '70d5159d-a0e4-46ca-b011-c4f831f4ade0' };
        const commit = vi.fn(async () => {
            throw new Error('Lost action result');
        });
        const cancel = vi.fn(async () => {});
        const prepare = vi.spyOn(owner.access, 'prepareSessionAction').mockResolvedValue(
            new SessionActionConfirmation(
                {
                    action: 'disconnect',
                    target,
                    expiresAt: '2100-01-01T00:00:00Z',
                },
                commit,
                cancel,
            ),
        );
        const workspace = await mountWorkspace(owner.access);
        await click(button(t('workspaceSessions')));
        const targetForm = await openSessionTarget(workspace.container);
        await fill(t('managementActionFlow'), target.flow);
        await fill(t('managementActionID'), target.id);
        await sessionTargetAction(targetForm, 'Disconnect connections');
        await click(button('Go'));
        await fill(t('managementConfirmTarget'), `${target.flow}/${target.id}`);
        await click(button(t('managementConfirmAction')));
        expect(workspace.onActionLock).toHaveBeenLastCalledWith(true);
        expect(workspace.container.textContent).toContain(t('managementActionUnknown'));
        const reads = owner.transport.mock.calls.length;
        await expired(owner.access);
        await workspace.render();
        expect(button(accessMessages.reauthenticate).disabled).toBe(true);
        await click(button(accessMessages.reauthenticate));
        expect(workspace.onSignIn).not.toHaveBeenCalled();
        expect(workspace.onActionLock).toHaveBeenLastCalledWith(true);
        expect(workspace.container.textContent).toContain(t('managementActionUnknown'));
        expect(prepare).toHaveBeenCalledTimes(1);
        expect(commit).toHaveBeenCalledTimes(1);
        expect(cancel).not.toHaveBeenCalled();
        expect(owner.transport).toHaveBeenCalledTimes(reads);
        noAuthenticationOrSavedReads();
        await click(button(t('managementDismissUnknown')));
        expect(button(accessMessages.reauthenticate).disabled).toBe(false);
        await click(button(accessMessages.reauthenticate));
        expect(workspace.onSignIn).toHaveBeenCalledExactlyOnceWith(owner.access.snapshot().scope);
    });
});
