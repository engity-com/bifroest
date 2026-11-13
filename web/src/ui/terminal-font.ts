import { useSyncExternalStore } from 'react';
import { reportUiError } from './error-report';
import { profilePreferencesResetEvent } from './profile-reset';

export const terminalFontPreferenceKey = 'bifroest-ui-v1:terminal-font-size';
const changed = 'bifroest-terminal-font-size';
export const defaultTerminalFontSize = 14;
let memory = defaultTerminalFontSize;
let lastStored: string | null | undefined;
export function preferredTerminalFontSize(): number {
    try {
        const value = localStorage.getItem(terminalFontPreferenceKey);
        if (value !== lastStored) {
            const size =
                value !== null && /^\d{1,2}$/u.test(value)
                    ? Number(value)
                    : defaultTerminalFontSize;
            memory = size >= 8 && size <= 40 ? size : defaultTerminalFontSize;
            lastStored = value;
        }
    } catch {
        /* A denied store does not prevent volatile, synchronized zoom. */
    }
    return memory;
}
export function adjustTerminalFontSize(delta: number): number {
    memory = Math.max(8, Math.min(40, preferredTerminalFontSize() + delta));
    try {
        localStorage.setItem(terminalFontPreferenceKey, String(memory));
        lastStored = String(memory);
    } catch (error) {
        reportUiError('preferences', error);
    }
    window.dispatchEvent(new Event(changed));
    return memory;
}
function subscribe(listener: () => void) {
    const reset = () => {
        lastStored = undefined;
        memory = defaultTerminalFontSize;
        listener();
    };
    const storage = (event: StorageEvent) => {
        if (event.key === terminalFontPreferenceKey || event.key === null) {
            reset();
        }
    };
    window.addEventListener(changed, listener);
    window.addEventListener('storage', storage);
    window.addEventListener(profilePreferencesResetEvent, reset);
    return () => {
        window.removeEventListener(changed, listener);
        window.removeEventListener('storage', storage);
        window.removeEventListener(profilePreferencesResetEvent, reset);
    };
}
export function useTerminalFontSize(): number {
    return useSyncExternalStore(
        subscribe,
        preferredTerminalFontSize,
        () => defaultTerminalFontSize,
    );
}
export function terminalZoomKey(
    event: Pick<KeyboardEvent, 'ctrlKey' | 'metaKey' | 'altKey' | 'key' | 'code' | 'isComposing'>,
): number {
    if (!event.ctrlKey || event.metaKey || event.altKey || event.isComposing) {
        return 0;
    }
    return event.key === '+' || event.key === '=' || event.code === 'NumpadAdd'
        ? 1
        : event.key === '-' || event.code === 'NumpadSubtract'
          ? -1
          : 0;
}
