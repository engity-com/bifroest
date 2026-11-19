import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { OidcLogin } from '../src/login/OidcLogin';
import * as protocol from '../src/login/oidc';

vi.mock('../src/login/oidc', { spy: true });

const first = 'A'.repeat(43);
const second = 'E'.repeat(43);
const cleanups: (() => void)[] = [];

beforeEach(() => {
    vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
    const url = location.href;
    cleanups.push(() => history.replaceState(null, '', url));
    vi.spyOn(window, 'close').mockImplementation(() => {});
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

function approval(id: string): protocol.OidcView {
    return {
        id,
        status: 'approval',
        ssh: true,
        flow: id === first ? 'first' : 'second',
        principal: id === first ? 'alice' : 'bob',
        choices: ['C3', 'V4', 'T7'],
        csrf: id,
    };
}

async function mount() {
    history.replaceState(null, '', `/login/#attempt/${first}`);
    const host = document.createElement('div');
    document.body.append(host);
    const root = createRoot(host);
    cleanups.push(() => {
        root.unmount();
        host.remove();
    });
    await act(async () => {
        root.render(createElement(OidcLogin));
    });
    return host;
}

async function navigate(hash: string) {
    await act(async () => {
        history.replaceState(null, '', `/login/${hash}`);
        window.dispatchEvent(new HashChangeEvent('hashchange'));
    });
}

function choice(host: HTMLElement): HTMLButtonElement {
    const button = host.querySelector<HTMLButtonElement>('[aria-label="Code C3"]');
    expect(button).not.toBeNull();
    if (!button) {
        throw new Error('Missing code choice');
    }
    return button;
}

it.each(['accepted', 'denied', 'aborted'] as const)(
    'ignores an old %s decision after navigating to another login',
    async (outcome) => {
        const pending = Promise.withResolvers<protocol.OidcView>();
        let signal: AbortSignal | undefined;
        const request = vi
            .mocked(protocol.oidcRequest)
            .mockImplementation(async (action, fields, stopped) => {
                if (action === 'approve') {
                    signal = stopped;
                    return pending.promise;
                }
                return fields.id === first
                    ? approval(first)
                    : { id: second, status: 'authorizing', ssh: true, flow: 'second' };
            });
        const host = await mount();
        await act(async () => {
            choice(host).click();
        });
        await navigate(`#attempt/${second}`);
        expect(signal?.aborted).toBe(true);
        expect(request).toHaveBeenCalledWith('status', { id: second }, expect.any(AbortSignal));
        await act(async () => {
            if (outcome === 'aborted') {
                pending.reject(new protocol.OidcError());
            } else {
                pending.resolve({ id: first, status: outcome, ssh: true, flow: 'first' });
            }
        });
        expect(host.querySelector('h1')?.textContent).toBe('Signing in');
        expect(window.close).not.toHaveBeenCalled();
    },
);

it('keeps a new decision locked when an older decision finishes', async () => {
    const oldDecision = Promise.withResolvers<protocol.OidcView>();
    const newDecision = Promise.withResolvers<protocol.OidcView>();
    const request = vi.mocked(protocol.oidcRequest).mockImplementation(async (action, fields) => {
        if (action === 'approve') {
            return fields.id === first ? oldDecision.promise : newDecision.promise;
        }
        return approval(fields.id ?? '');
    });
    const host = await mount();
    await act(async () => {
        choice(host).click();
    });
    await navigate(`#attempt/${second}`);
    expect(choice(host).disabled).toBe(false);
    await act(async () => {
        choice(host).click();
    });
    expect(request).toHaveBeenCalledWith(
        'approve',
        expect.objectContaining({ id: second }),
        expect.any(AbortSignal),
    );
    expect(choice(host).disabled).toBe(true);
    await act(async () => {
        oldDecision.resolve({ id: first, status: 'accepted', ssh: true, flow: 'first' });
    });
    expect(choice(host).disabled).toBe(true);
    expect(host.querySelector('h1')?.textContent).toBe('Confirm your SSH login');
    await act(async () => {
        newDecision.resolve({ id: second, status: 'authorizing', ssh: true, flow: 'second' });
    });
    expect(host.querySelector('h1')?.textContent).toBe('Signing in');
});

it('ignores an old decision after returning to the waiting route', async () => {
    const pending = Promise.withResolvers<protocol.OidcView>();
    vi.mocked(protocol.oidcRequest).mockImplementation(async (action) =>
        action === 'approve' ? pending.promise : approval(first),
    );
    const host = await mount();
    await act(async () => {
        choice(host).click();
    });
    await navigate('#waiting');
    await act(async () => {
        pending.resolve({ id: first, status: 'accepted', ssh: true, flow: 'first' });
    });
    expect(host.querySelector('h1')?.textContent).toBe('Signing in');
    expect(window.close).not.toHaveBeenCalled();
});
