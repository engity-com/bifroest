import { afterEach, describe, expect, it } from 'vitest';
import { keepAliveDuration, keepAlivePolicy } from '../src/terminal/keepalive';
import {
    keepAlivePreferencePrefix,
    preferredKeepAlive,
    saveKeepAlivePreference,
} from '../src/ui/preferences';

const scope = { origin: location.origin, slug: 'Work' };
afterEach(() => {
    for (const key of Object.keys(localStorage)) {
        if (key.startsWith(keepAlivePreferencePrefix)) {
            localStorage.removeItem(key);
        }
    }
});

describe('flow keepalive duration and non-authentication preferences', () => {
    it('matches bounded Go durations without floating-point rounding or a client lock prefix', () => {
        for (const input of [
            '1s',
            '+1s',
            '1000ms',
            '1.s',
            '1m30.5s',
            '5m',
            '1000000us',
            '1000000µs',
            '1000000μs',
        ]) {
            expect(keepAliveDuration(input)).not.toBeNull();
        }
        for (const input of [
            '',
            '0',
            '0s',
            '!10s',
            ' 10s',
            '1s ',
            '-1s',
            '999999999.999ns',
            '5m1ns',
            '1h',
            '15',
            'NaNs',
            '1e2s',
            'x'.repeat(65),
        ]) {
            expect(keepAliveDuration(input)).toBeNull();
        }
        expect(keepAliveDuration('1m30.5s')).toBe(90500000000n);
        const multibyte = `1s${'0µs'.repeat(20)}`;
        expect(multibyte.length).toBe(62);
        expect(new TextEncoder().encode(multibyte).byteLength).toBe(82);
        expect(keepAliveDuration(multibyte)).toBeNull();
    });
    it('accepts only exact, safe server policy fields', () => {
        expect(keepAlivePolicy({ interval: '10s', locked: true })).toEqual({
            interval: '10s',
            locked: true,
        });
        for (const policy of [
            { interval: '10s', locked: 'true' },
            { interval: '!10s', locked: true },
            { interval: '10s', locked: false, bearer: 'PRIVATE' },
        ]) {
            expect(() => keepAlivePolicy(policy)).toThrow();
        }
    });
    it('stores only a valid interval per origin/link and ignores corrupt or foreign state', () => {
        saveKeepAlivePreference(scope, '10s');
        expect(preferredKeepAlive(scope)).toBe('10s');
        expect(preferredKeepAlive({ ...scope, slug: 'Other' })).toBeUndefined();
        expect(preferredKeepAlive({ ...scope, origin: 'https://foreign.invalid' })).toBeUndefined();
        saveKeepAlivePreference(scope, '!1s');
        expect(preferredKeepAlive(scope)).toBe('10s');
        localStorage.setItem(`${keepAlivePreferencePrefix}Work`, 'PRIVATE-INVALID');
        expect(preferredKeepAlive(scope)).toBeUndefined();
    });
});
