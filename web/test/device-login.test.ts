import { act, createElement, StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, expect, it, vi } from 'vitest';
import { DeviceLogin } from '../src/login/DeviceLogin';

const cleanups: (() => void)[] = [];
afterEach(async () => {
    await act(async () => {
        for (const cleanup of cleanups.splice(0)) {
            cleanup();
        }
    });
    vi.restoreAllMocks();
});
const device = { userCode: 'ABCD-EFGH', url: 'https://idp.example.org/device' };
async function mount(ready = true) {
    const host = document.createElement('div');
    document.body.append(host);
    const root = createRoot(host);
    const onContinue = vi.fn();
    const onCancel = vi.fn();
    const render = async (next: boolean) =>
        act(async () => {
            root.render(
                createElement(
                    StrictMode,
                    null,
                    createElement(DeviceLogin, { device, ready: next, onContinue, onCancel }),
                ),
            );
        });
    cleanups.push(() => {
        root.unmount();
        host.remove();
    });
    await render(ready);
    return { host, render, onContinue, onCancel };
}

it('copies immediately on arrival, shows the code once and keeps DeviceAuth in a compact dialog view', async () => {
    const write = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue();
    const popup = { opener: window, location: { replace: vi.fn() } };
    const open = vi.spyOn(window, 'open').mockReturnValue(popup as unknown as Window);
    const ui = await mount();
    expect(write).toHaveBeenCalledExactlyOnceWith(device.userCode);
    expect(open).not.toHaveBeenCalled();
    expect(ui.host.textContent).toContain('is copied to your clipboard');
    expect(ui.host.textContent?.split(device.userCode)).toHaveLength(2);
    expect(ui.host.querySelector('.terminal-surface')).toBeNull();
    await act(async () => {
        ui.host.querySelector('a')?.click();
    });
    expect(ui.onContinue).toHaveBeenCalledOnce();
    expect(popup.location.replace).toHaveBeenCalledExactlyOnceWith(device.url);
    expect(write).toHaveBeenCalledOnce();
    await ui.render(false);
    expect(ui.host.textContent).toContain('Waiting for authentication');
    expect(ui.host.textContent?.split(device.userCode)).toHaveLength(2);
    expect(write).toHaveBeenCalledOnce();
    expect(ui.host.textContent).not.toContain('Press Enter');
});

it('uses a manual instruction after denied clipboard access and only retries copying on explicit request', async () => {
    const write = vi
        .spyOn(navigator.clipboard, 'writeText')
        .mockRejectedValue(new Error('private browser diagnostic'));
    vi.spyOn(window, 'open').mockReturnValue(null);
    const ui = await mount();
    expect(ui.host.textContent).toContain(
        `Enter code ${device.userCode} on the verification page.`,
    );
    expect(ui.host.textContent).not.toContain('copied to your clipboard');
    expect(ui.host.textContent).not.toContain('private browser diagnostic');
    await act(async () => {
        ui.host.querySelector('a')?.click();
    });
    expect(ui.host.textContent).toContain('Popup blocked');
    expect(write).toHaveBeenCalledOnce();
    write.mockResolvedValueOnce();
    await act(async () => {
        ui.host.querySelector<HTMLButtonElement>('button[aria-label="Copy device code"]')?.click();
    });
    expect(write).toHaveBeenCalledTimes(2);
    expect(ui.host.textContent).toContain('is copied to your clipboard');
});
