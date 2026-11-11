import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { expect, it, vi } from 'vitest';
import {
    LoginDialog,
    type LoginDialogActions,
    type LoginDialogState,
} from '../src/login/LoginDialog';

it('keeps Saved, Password, Interactive and SSH key as four tabs with a field-free Saved form', async () => {
    const state: LoginDialogState = {
        open: true,
        ready: true,
        metadata: {
            scope: { origin: location.origin, slug: 'Work' },
            rootAvailable: false,
            publishedSlugs: ['Work'],
            loginOptions: (['password', 'keyboard-interactive', 'public-key'] as const).map(
                (method) => ({
                    method,
                    requestUser: true,
                    certificateRequired: false,
                    rememberMe: 'allowed',
                }),
            ),
        },
        route: { slug: 'Work', origin: location.origin, failed: false, links: ['Work'] },
        saved: 'ready',
        activeUsesScope: false,
        notice: null,
        choice: 'saved',
        user: 'alice',
        optIn: false,
        inputRevision: 0,
        busy: false,
        managementLocked: false,
        rememberUncertain: false,
    };
    const actions: LoginDialogActions = {
        close: vi.fn(),
        chooseLink: vi.fn(),
        chooseMethod: vi.fn(),
        changeUser: vi.fn(),
        changeOptIn: vi.fn(),
        submit: vi.fn(),
        cancel: vi.fn(),
        resume: vi.fn(),
        confirmSaved: vi.fn(),
        retryMetadata: vi.fn(),
        showNotice: vi.fn(),
    };
    const container = document.createElement('div');
    document.body.append(container);
    const root = createRoot(container);
    try {
        await act(async () => {
            root.render(createElement(LoginDialog, { state, actions }));
        });
        const dialog = document.querySelector('.login-dialog');
        expect(dialog).not.toBeNull();
        const choices = [...(dialog?.querySelectorAll('[role="radio"]') ?? [])];
        expect(choices.map((choice) => choice.getAttribute('value'))).toEqual([
            'saved',
            'password:named',
            'keyboard-interactive:named',
            'public-key:named',
        ]);
        expect(choices[0]?.getAttribute('aria-checked')).toBe('true');
        expect(dialog?.querySelector('[role="combobox"]')).toBeNull();
        expect(dialog?.querySelectorAll('form input')).toHaveLength(0);
        expect(dialog?.textContent).toContain('Use your last saved login.');
        expect(actions.resume).not.toHaveBeenCalled();
        await act(async () => {
            dialog
                ?.querySelector('form')
                ?.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
        });
        expect(actions.resume).toHaveBeenCalledOnce();
        expect(actions.submit).not.toHaveBeenCalled();
    } finally {
        await act(async () => {
            root.unmount();
        });
        container.remove();
    }
});
