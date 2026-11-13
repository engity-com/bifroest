import { afterEach, expect, it, vi } from 'vitest';
import {
    adjustTerminalFontSize,
    preferredTerminalFontSize,
    terminalFontPreferenceKey,
    terminalZoomKey,
} from '../src/ui/terminal-font';

afterEach(() => {
    localStorage.removeItem(terminalFontPreferenceKey);
    vi.restoreAllMocks();
});
it('persists a bounded domain-wide font preference without any account, tab or credential selector', () => {
    adjustTerminalFontSize(100);
    expect(preferredTerminalFontSize()).toBe(40);
    expect(localStorage.getItem(terminalFontPreferenceKey)).toBe('40');
    adjustTerminalFontSize(-100);
    expect(preferredTerminalFontSize()).toBe(8);
    adjustTerminalFontSize(6);
    expect(preferredTerminalFontSize()).toBe(14);
    expect(terminalFontPreferenceKey).not.toMatch(/slug|actor|session|token/u);
});
it('owns only Ctrl plus/minus zoom gestures, not composition, platform keys or unrelated input', () => {
    const base = {
        ctrlKey: true,
        metaKey: false,
        altKey: false,
        isComposing: false,
        key: '+',
        code: 'Equal',
    };
    expect(terminalZoomKey(base)).toBe(1);
    expect(terminalZoomKey({ ...base, key: '-', code: 'Minus' })).toBe(-1);
    expect(terminalZoomKey({ ...base, key: '=', code: 'Equal' })).toBe(1);
    for (const changes of [
        { ctrlKey: false },
        { metaKey: true },
        { altKey: true },
        { isComposing: true },
        { key: 'd', code: 'KeyD' },
    ]) {
        expect(terminalZoomKey({ ...base, ...changes })).toBe(0);
    }
});
