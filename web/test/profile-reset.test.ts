import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { WebAccess } from '../src/remember';
import { BrowserBinding } from '../src/remember';
import { resetProfile } from '../src/ui/profile-reset';

const database = 'bifroest-browser-remember-v1';
async function cleanDatabase() {
    await new Promise<void>((resolve, reject) => {
        const request = indexedDB.deleteDatabase(database);
        request.onsuccess = () => resolve();
        request.onerror = request.onblocked = () =>
            reject(new Error('Owned fixture database blocked'));
    });
}
beforeEach(async () => {
    await cleanDatabase();
    localStorage.setItem('bifroest-ui-v1:theme', 'dark');
    localStorage.setItem('bifroest-ui-v1:details', 'compact');
});
afterEach(async () => {
    vi.restoreAllMocks();
    for (const key of Object.keys(localStorage)) {
        if (key.startsWith('bifroest-')) {
            localStorage.removeItem(key);
        }
    }
    await cleanDatabase();
});
function fixture() {
    const logout = vi.fn(async () => ({ localState: 'removed' as const }));
    const retire = vi.fn(async () => {});
    const close = vi.fn(() => true);
    const access = {
        snapshot: () => ({ scope: { origin: location.origin, slug: 'Work' } }),
        rememberedBindingForReset: () => null,
        logout,
        retireForReset: retire,
    } as unknown as WebAccess;
    return { access, logout, retire, close };
}

it('requires explicit confirmation without touching settings, credentials, views or remote endpoints', async () => {
    const owned = fixture();
    await expect(
        resetProfile({
            explicitConfirmation: false,
            accesses: [owned.access],
            closeViews: owned.close,
        }),
    ).rejects.toThrow();
    expect(localStorage.getItem('bifroest-ui-v1:theme')).toBe('dark');
    expect(owned.logout).not.toHaveBeenCalled();
    expect(owned.retire).not.toHaveBeenCalled();
    expect(owned.close).not.toHaveBeenCalled();
    expect((await indexedDB.databases()).some((value) => value.name === database)).toBe(false);
});
it('forgets the local profile and retires capabilities even if remote logout fails, without retrying it', async () => {
    const owned = fixture();
    owned.logout.mockRejectedValue(new Error('PRIVATE-TRANSPORT-DIAGNOSTIC'));
    const result = await resetProfile({
        explicitConfirmation: true,
        accesses: [owned.access, owned.access],
        closeViews: owned.close,
    });
    expect(result).toEqual({ localCleared: true, remoteUnconfirmed: 1, viewsClosed: true });
    expect(owned.logout).toHaveBeenCalledTimes(1);
    expect(owned.retire).toHaveBeenCalledTimes(1);
    expect(owned.close).toHaveBeenCalledOnce();
    expect(Object.keys(localStorage).some((key) => key.startsWith('bifroest-'))).toBe(false);
    expect(JSON.stringify(result)).not.toContain('PRIVATE');
    expect(await BrowserBinding.clearForReset({ explicitConfirmation: true })).toBe(0);
});
it('still forgets locally with an already-cancelled network budget and reports unconfirmed remote work', async () => {
    const owned = fixture();
    const controller = new AbortController();
    controller.abort();
    const result = await resetProfile({
        explicitConfirmation: true,
        accesses: [owned.access],
        closeViews: owned.close,
        signal: controller.signal,
    });
    expect(result.localCleared).toBe(true);
    expect(result.remoteUnconfirmed).toBe(1);
    expect(owned.logout).not.toHaveBeenCalled();
    expect(owned.retire).toHaveBeenCalledOnce();
});
it('does not claim local cleanup or view closure when storage or the operation-owner guard refuses', async () => {
    const owned = fixture();
    owned.close.mockReturnValue(false);
    const blocked = vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => {
        throw new DOMException('blocked', 'SecurityError');
    });
    try {
        const result = await resetProfile({
            explicitConfirmation: true,
            accesses: [owned.access],
            closeViews: owned.close,
        });
        expect(result).toEqual({ localCleared: false, remoteUnconfirmed: 0, viewsClosed: false });
        expect(localStorage.getItem('bifroest-ui-v1:theme')).toBe('dark');
        expect(owned.logout).toHaveBeenCalledOnce();
        expect(owned.retire).toHaveBeenCalledOnce();
    } finally {
        blocked.mockRestore();
    }
});
