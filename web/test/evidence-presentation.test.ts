import { act, createElement, StrictMode, useLayoutEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { page } from 'vitest/browser';
import { EvidenceVerificationToolbar } from '../src/artifacts/EvidenceVerificationToolbar';
import type { LocalKeyInput } from '../src/artifacts/local-key-input-view';
import { useLocalKeyInput } from '../src/artifacts/use-local-key-input';
import { LocalKeyFields } from '../src/artifacts/VerificationFields';
import { t } from '../src/ui/messages';

const cleanups: (() => void)[] = [];
beforeEach(() => vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true));
afterEach(async () => {
    await act(async () => {
        for (const cleanup of cleanups.splice(0).reverse()) {
            cleanup();
        }
    });
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
});
interface Inputs {
    verification: LocalKeyInput;
    decryption: LocalKeyInput;
}
function InputProbe({
    verificationVisible,
    changed,
}: {
    verificationVisible: boolean;
    changed(value: Inputs): void;
}) {
    const verification = useLocalKeyInput();
    const decryption = useLocalKeyInput();
    useLayoutEffect(() => changed({ verification, decryption }));
    return createElement(
        'div',
        null,
        verificationVisible &&
            createElement(
                'section',
                { 'aria-label': 'verification' },
                createElement(LocalKeyFields, { ...verification.fields, disabled: false }),
            ),
        createElement(
            'section',
            { 'aria-label': 'decryption' },
            createElement(LocalKeyFields, { ...decryption.fields, disabled: false }),
        ),
    );
}
function host() {
    const container = document.createElement('div');
    document.body.append(container);
    const root = createRoot(container);
    cleanups.push(() => {
        root.unmount();
        container.remove();
    });
    return { container, root };
}

it.each([false, true])(
    'keeps sibling key forms independent during clearing and portal retirement (StrictMode=%s)',
    async (strict) => {
        const { root } = host();
        let latest: Inputs | undefined;
        const current = () => {
            if (!latest) {
                throw new Error('Missing input bindings');
            }
            return latest;
        };
        const render = async (verificationVisible: boolean) =>
            act(async () => {
                const content = createElement(InputProbe, {
                    verificationVisible,
                    changed: (value) => {
                        latest = value;
                    },
                });
                root.render(strict ? createElement(StrictMode, null, content) : content);
            });
        const fill = async (kind: keyof Inputs, name: string, passphrase: string) => {
            const input = current()[kind].fields.input.current;
            if (!input) {
                throw new Error('Missing file input');
            }
            await act(async () =>
                page.elementLocator(input).upload(new File([`PRIVATE-${name}`], name)),
            );
            const password = current()[kind].fields.form.current?.querySelector<HTMLInputElement>(
                '[name="evidence-passphrase"]',
            );
            if (!password) {
                throw new Error('Missing passphrase input');
            }
            await act(async () => page.elementLocator(password).fill(passphrase));
        };
        await render(true);
        expect(current().verification.fields.id).not.toBe(current().decryption.fields.id);
        expect(current().verification.read()).toEqual({ file: undefined, passphrase: '' });
        await fill('verification', 'verify.key', 'VERIFY-PRIVATE-PASSPHRASE');
        await fill('decryption', 'decrypt.key', 'DECRYPT-PRIVATE-PASSPHRASE');
        const original = current().verification.read().file;
        expect(await original?.text()).toBe('PRIVATE-verify.key');
        await act(async () => current().verification.clear());
        expect(current().verification.fields.candidate).toBe(false);
        expect(current().verification.read()).toEqual({ file: undefined, passphrase: '' });
        expect(await original?.text()).toBe('PRIVATE-verify.key');
        expect(current().decryption.fields.candidate).toBe(true);
        expect(current().decryption.read().passphrase).toBe('DECRYPT-PRIVATE-PASSPHRASE');
        await render(false);
        expect(current().verification.fields.input.current).toBeNull();
        expect(current().decryption.read().file?.name).toBe('decrypt.key');
        expect(current().decryption.read().passphrase).toBe('DECRYPT-PRIVATE-PASSPHRASE');
        await act(async () => current().decryption.clear());
        expect(current().decryption.read()).toEqual({ file: undefined, passphrase: '' });
        expect(Object.keys(current().decryption.fields)).not.toContain('passphrase');
        expect(Object.keys(current().decryption.fields)).not.toContain('file');
    },
);

it('dispatches verification toolbar commands only on enabled explicit gestures', async () => {
    const { root, container } = host();
    const onDetails = vi.fn();
    const onVerify = vi.fn();
    const onCancel = vi.fn();
    const render = async (busy: boolean, disabled: boolean) =>
        act(async () =>
            root.render(
                createElement(EvidenceVerificationToolbar, {
                    result: 'success',
                    busy,
                    disabled,
                    verifyDisabled: disabled,
                    showVerify: true,
                    onDetails,
                    onVerify,
                    onCancel,
                }),
            ),
        );
    const click = async (label: string) => {
        const button = container.querySelector<HTMLButtonElement>(`button[aria-label="${label}"]`);
        if (!button) {
            throw new Error('Missing toolbar command');
        }
        await act(async () => button.click());
    };
    await render(false, true);
    expect(onVerify).not.toHaveBeenCalled();
    expect(onCancel).not.toHaveBeenCalled();
    expect(onDetails).not.toHaveBeenCalled();
    await click(t('verifyOpen'));
    expect(onVerify).not.toHaveBeenCalled();
    await render(false, false);
    await click(t('verifyOpen'));
    expect(onVerify).toHaveBeenCalledOnce();
    expect(onCancel).not.toHaveBeenCalled();
    await render(true, false);
    await click(t('artifactCancel'));
    expect(onCancel).toHaveBeenCalledOnce();
    expect(onVerify).toHaveBeenCalledOnce();
});
