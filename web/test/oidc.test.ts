import { describe, expect, it, vi } from 'vitest';
import { oidcEntry, oidcRequest } from '../src/login/oidc';

const id = 'A'.repeat(43);
describe('bounded standalone OIDC protocol', () => {
    it('takes start tickets only from fragments and callback queries only on the fixed callback route', () => {
        expect(oidcEntry({ pathname: '/login/', search: '', hash: `#start/${id}` })).toEqual({
            action: 'start',
            fields: { ticket: id },
        });
        expect(oidcEntry({ pathname: '/login/', search: '', hash: `#attempt/${id}` })).toEqual({
            action: 'status',
            fields: { id },
        });
        expect(
            oidcEntry({ pathname: '/login/callback', search: '?state=x&code=y', hash: '' }),
        ).toEqual({ action: 'callback', fields: { query: 'state=x&code=y' } });
        for (const pathname of ['/docker', '/sso', '/api/v1/oidc/start']) {
            expect(oidcEntry({ pathname, search: '', hash: `#start/${id}` })).toBeNull();
        }
        expect(oidcEntry({ pathname: '/login/', search: `?ticket=${id}`, hash: '' })).toBeNull();
    });
    it('uses only same-origin JSON API POSTs and validates three distinct comparison choices', async () => {
        const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
            new Response(
                JSON.stringify({
                    id,
                    status: 'approval',
                    ssh: true,
                    flow: 'shell',
                    principal: 'alice',
                    choices: ['C3', 'V4', 'T7'],
                    csrf: id,
                }),
                { headers: { 'Content-Type': 'application/json' } },
            ),
        );
        try {
            const view = await oidcRequest('status', { id }, new AbortController().signal);
            expect(view.choices).toEqual(['C3', 'V4', 'T7']);
            expect(fetcher).toHaveBeenCalledWith(
                '/api/v1/oidc/status',
                expect.objectContaining({
                    method: 'POST',
                    credentials: 'same-origin',
                    redirect: 'error',
                    mode: 'same-origin',
                    cache: 'no-store',
                    body: JSON.stringify({ id }),
                }),
            );
            for (const invalid of [
                { ...view, ssh: false },
                { ...view, choices: ['C3', 'C3', 'T7'] },
                { ...view, choices: ['O0', 'V4', 'T7'] },
                { ...view, status: 'accepted' },
                { ...view, accessToken: 'never-a-workload-credential' },
                { ...view, url: 'javascript:alert(1)' },
            ]) {
                fetcher.mockResolvedValueOnce(
                    new Response(JSON.stringify(invalid), {
                        headers: { 'Content-Type': 'application/json' },
                    }),
                );
                await expect(
                    oidcRequest('status', { id }, new AbortController().signal),
                ).rejects.toThrow('OIDC login unavailable');
            }
        } finally {
            fetcher.mockRestore();
        }
    });
});
