import { afterEach, describe, expect, it, vi } from 'vitest';
import { copyDeviceCode, openDeviceLogin } from '../src/login/device';
import { terminalClipboardKey } from '../src/terminal/clipboard';

afterEach(() => {
    vi.restoreAllMocks();
});

const key = (letter: string, options: KeyboardEventInit = {}) =>
    new KeyboardEvent('keydown', {
        key: letter,
        ctrlKey: true,
        shiftKey: true,
        cancelable: true,
        ...options,
    });
function clipboard() {
    const write = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue();
    const read = vi.spyOn(navigator.clipboard, 'readText').mockResolvedValue('pasted text');
    return { write, read };
}
describe('terminal clipboard shortcuts', () => {
    it('copies the selection and pastes through the owning input path without Ctrl+C/Ctrl+V bytes', async () => {
        const c = clipboard();
        const paste = vi.fn();
        const ports = {
            active: () => true,
            selection: () => 'selected text',
            capturePaste: () => paste,
            failed: vi.fn(),
        };
        const copy = key('C');
        expect(terminalClipboardKey(copy, ports)).toBe(true);
        expect(copy.defaultPrevented).toBe(true);
        expect(c.write).toHaveBeenCalledExactlyOnceWith('selected text');
        expect(terminalClipboardKey(key('V'), ports)).toBe(true);
        await vi.waitFor(() => expect(paste).toHaveBeenCalledExactlyOnceWith('pasted text'));
        expect(terminalClipboardKey(key('c', { shiftKey: false }), ports)).toBe(false);
        expect(terminalClipboardKey(key('v', { isComposing: true }), ports)).toBe(false);
        expect(terminalClipboardKey(key('c', { keyCode: 229 }), ports)).toBe(false);
        expect(terminalClipboardKey(key('c'), { ...ports, active: () => false })).toBe(false);
    });
    it('does not paste a late clipboard response into a retired terminal and reports permission failures', async () => {
        const c = clipboard();
        const result = Promise.withResolvers<string>();
        c.read.mockReturnValueOnce(result.promise);
        let active = true;
        const paste = vi.fn();
        const failed = vi.fn();
        const ports = {
            active: () => active,
            selection: () => '',
            capturePaste: () => paste,
            failed,
        };
        terminalClipboardKey(key('v'), ports);
        active = false;
        result.resolve('stale paste');
        await result.promise;
        expect(paste).not.toHaveBeenCalled();
        active = true;
        c.read.mockRejectedValueOnce(new Error('private clipboard diagnostic'));
        terminalClipboardKey(key('v'), ports);
        await vi.waitFor(() => expect(failed).toHaveBeenCalledOnce());
    });
});

describe('explicit browser device authorization action', () => {
    it('opens the provider on an explicit gesture without copying the code again', () => {
        const c = clipboard();
        const popup = { opener: window, location: { replace: vi.fn() } };
        const open = vi.spyOn(window, 'open').mockReturnValue(popup as unknown as Window);
        const opened = openDeviceLogin('https://idp.example.org/device?user_code=ABCD-EFGH');
        expect(c.write).not.toHaveBeenCalled();
        expect(open).toHaveBeenCalledExactlyOnceWith('about:blank', '_blank');
        expect(popup.location.replace).toHaveBeenCalledExactlyOnceWith(
            'https://idp.example.org/device?user_code=ABCD-EFGH',
        );
        expect(popup.opener).toBeNull();
        expect(opened).toBe(true);
    });
    it('reports blocked popups and failed clipboard access without claiming the code was copied', async () => {
        const c = clipboard();
        c.write.mockRejectedValue(new Error('clipboard denied'));
        vi.spyOn(window, 'open').mockReturnValue(null);
        expect(openDeviceLogin('https://idp.example.org/device')).toBe(false);
        expect(await copyDeviceCode('ABCD')).toBe(false);
    });
});
