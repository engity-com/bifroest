import type { Scope } from '../remember';
import { keepAliveDuration } from '../terminal/keepalive';
import { reportUiError } from './error-report';

export const themePreferenceKey = 'bifroest-ui-v1:theme';
export const usernamePreferencePrefix = 'bifroest-ui-v1:username:';
export const keepAlivePreferencePrefix = 'bifroest-ui-v1:keepalive:';
export type ThemePreference = 'auto' | 'light' | 'dark';
export function isThemePreference(value: unknown): value is ThemePreference {
    return value === 'auto' || value === 'light' || value === 'dark';
}
export function validPreferredUsername(value: unknown): value is string {
    return (
        typeof value === 'string' &&
        value.length > 0 &&
        value.length <= 256 &&
        value.isWellFormed() &&
        value.trim().length > 0 &&
        !/[\p{Cc}]/u.test(value) &&
        new TextEncoder().encode(value).byteLength <= 256
    );
}
function usernameKey(scope: Scope): string | null {
    return scope.origin === location.origin &&
        /^(?:[A-Za-z0-9]{1,64}(?:\/[A-Za-z0-9]{1,64})?)?$/u.test(scope.slug)
        ? usernamePreferencePrefix + encodeURIComponent(scope.slug)
        : null;
}
export function preferredTheme(): ThemePreference {
    try {
        const value = localStorage.getItem(themePreferenceKey);
        return isThemePreference(value) ? value : 'auto';
    } catch (error) {
        reportUiError('preferences', error);
        return 'auto';
    }
}
export function saveThemePreference(value: ThemePreference): void {
    if (!isThemePreference(value)) {
        return;
    }
    try {
        localStorage.setItem(themePreferenceKey, value);
    } catch (error) {
        reportUiError('preferences', error);
    }
}
export function preferredUsername(scope: Scope): string {
    const key = usernameKey(scope);
    if (key === null) {
        return '';
    }
    try {
        const value = localStorage.getItem(key);
        return validPreferredUsername(value) ? value : '';
    } catch (error) {
        reportUiError('preferences', error);
        return '';
    }
}
// Call only for a confirmed primary login, with its ORIGINAL requested name.
// This is an editable preference, never identity, a selector or authorization.
export function saveSuccessfulUsername(scope: Scope, user: string): void {
    const key = usernameKey(scope);
    if (key === null || !validPreferredUsername(user)) {
        return;
    }
    try {
        localStorage.setItem(key, user);
    } catch (error) {
        reportUiError('preferences', error);
    }
}

export function preferredKeepAlive(scope: Scope): string | undefined {
    const userKey = usernameKey(scope);
    if (userKey === null) {
        return undefined;
    }
    try {
        const value = localStorage.getItem(
            keepAlivePreferencePrefix + encodeURIComponent(scope.slug),
        );
        return keepAliveDuration(value) !== null ? (value ?? undefined) : undefined;
    } catch (error) {
        reportUiError('preferences', error);
        return undefined;
    }
}

export function saveKeepAlivePreference(scope: Scope, interval: string): void {
    if (usernameKey(scope) === null || keepAliveDuration(interval) === null) {
        return;
    }
    try {
        localStorage.setItem(keepAlivePreferencePrefix + encodeURIComponent(scope.slug), interval);
    } catch (error) {
        reportUiError('preferences', error);
    }
}
