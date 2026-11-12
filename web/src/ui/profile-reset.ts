import type { ProfileResetResult } from '../application/reset-contracts';
import { BrowserBinding, BrowserClient, type WebAccess } from '../remember';
import { notifyProfileResetPeers } from './profile-reset-peers';

export const profileResetEvent = 'bifroest-profile-reset-start';
export const profilePreferencesResetEvent = 'bifroest-profile-preferences-reset';
function selectionKey(
    scope: { origin: string; slug: string },
    binding: { bindingId: string },
): string {
    return JSON.stringify([scope.origin, scope.slug, binding.bindingId]);
}
async function selectorHash(key: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key));
    return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, '0')).join('');
}
function clearPreferences(): boolean {
    let cleared = true;
    for (const storage of [() => localStorage, () => sessionStorage]) {
        try {
            const selected = storage();
            for (const key of Object.keys(selected)) {
                if (key.startsWith('bifroest-')) {
                    selected.removeItem(key);
                }
            }
        } catch {
            cleared = false;
        }
    }
    window.dispatchEvent(new Event(profilePreferencesResetEvent));
    return cleared;
}

// The one explicit reset path. No new login/resumption, configuration write,
// session disposal or private-key upload is used to clean up browser state.
export async function resetProfile(options: {
    explicitConfirmation: boolean;
    accesses: readonly WebAccess[];
    closeViews: () => boolean;
    signal?: AbortSignal;
}): Promise<ProfileResetResult> {
    if (options.explicitConfirmation !== true) {
        throw new Error('Explicit reset confirmation required');
    }
    const accesses = [...new Set(options.accesses)];
    if (accesses.some((access) => access.snapshot().scope.origin !== location.origin)) {
        throw new Error('Invalid reset origin');
    }
    window.dispatchEvent(new Event(profileResetEvent));
    let handles: BrowserBinding[] = [];
    let remoteUnconfirmed = 0;
    let localCleared = true;
    try {
        const selected = await BrowserBinding.selectionsForReset({
            origin: location.origin,
            explicitConfirmation: true,
        });
        handles = selected.handles;
        remoteUnconfirmed = selected.unconfirmed;
    } catch {
        remoteUnconfirmed++;
    }
    const covered = new Set(
        handles.flatMap((handle) =>
            handle.binding ? [selectionKey(handle.scope, handle.binding)] : [],
        ),
    );
    const peers = notifyProfileResetPeers(await Promise.all([...covered].map(selectorHash)));
    try {
        await BrowserBinding.clearForReset({ explicitConfirmation: true });
    } catch {
        localCleared = false;
    }
    localCleared = clearPreferences() && localCleared;
    const signal = options.signal
        ? AbortSignal.any([options.signal, AbortSignal.timeout(20_000)])
        : AbortSignal.timeout(20_000);
    const confirmed = new Set<string>();
    try {
        for (const access of accesses) {
            const binding = access.rememberedBindingForReset();
            const key = binding ? selectionKey(access.snapshot().scope, binding) : null;
            if (key !== null && covered.has(key)) {
                continue;
            }
            if (key !== null && confirmed.has(key)) {
                continue;
            }
            if (signal.aborted) {
                remoteUnconfirmed++;
                continue;
            }
            try {
                await access.logout(signal);
                const owned = access.rememberedBindingForReset() ?? binding;
                if (owned) {
                    confirmed.add(selectionKey(access.snapshot().scope, owned));
                }
            } catch {
                remoteUnconfirmed++;
            }
        }
        for (const handle of handles) {
            if (handle.binding === null) {
                remoteUnconfirmed++;
                continue;
            }
            const key = selectionKey(handle.scope, handle.binding);
            if (confirmed.has(key)) {
                continue;
            }
            if (signal.aborted) {
                remoteUnconfirmed++;
                continue;
            }
            try {
                await new BrowserClient(handle.scope).revokeSelection(handle, signal);
                confirmed.add(key);
            } catch {
                remoteUnconfirmed++;
            }
        }
    } finally {
        const retired = await Promise.allSettled(accesses.map((access) => access.retireForReset()));
        if (retired.some((result) => result.status === 'rejected')) {
            localCleared = false;
        }
        try {
            remoteUnconfirmed += await BrowserBinding.clearForReset({ explicitConfirmation: true });
        } catch {
            localCleared = false;
        }
        handles = [];
        localCleared = clearPreferences() && localCleared;
    }
    const peerResults = await peers.finish(signal);
    peers.close();
    remoteUnconfirmed += peerResults.reduce((count, value) => count + value.remoteUnconfirmed, 0);
    localCleared = localCleared && peerResults.every((value) => value.localCleared);
    return {
        localCleared,
        remoteUnconfirmed,
        viewsClosed: options.closeViews() && peerResults.every((value) => value.viewsClosed),
    };
}

export async function resetPeerContexts(options: {
    covered: readonly string[];
    accesses: readonly WebAccess[];
    closeViews: () => boolean;
}): Promise<ProfileResetResult> {
    if (options.accesses.some((access) => access.snapshot().scope.origin !== location.origin)) {
        return { localCleared: false, remoteUnconfirmed: 1, viewsClosed: false };
    }
    window.dispatchEvent(new Event(profileResetEvent));
    const signal = AbortSignal.timeout(20_000);
    let remoteUnconfirmed = 0;
    let localCleared = true;
    try {
        for (const access of new Set(options.accesses)) {
            if (access.snapshot().scope.origin !== location.origin) {
                remoteUnconfirmed++;
                continue;
            }
            const binding = access.rememberedBindingForReset();
            const hash = binding
                ? await selectorHash(selectionKey(access.snapshot().scope, binding))
                : null;
            if (hash !== null && options.covered.includes(hash)) {
                continue;
            }
            if (signal.aborted) {
                remoteUnconfirmed++;
                continue;
            }
            try {
                await access.logout(signal);
            } catch {
                remoteUnconfirmed++;
            }
        }
    } finally {
        const retired = await Promise.allSettled(
            options.accesses.map((access) => access.retireForReset()),
        );
        localCleared = retired.every((value) => value.status === 'fulfilled') && clearPreferences();
    }
    return { localCleared, remoteUnconfirmed, viewsClosed: options.closeViews() };
}
