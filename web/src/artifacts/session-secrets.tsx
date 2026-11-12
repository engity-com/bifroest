import { createContext, useContext, useLayoutEffect, useRef, useState } from 'react';
import type { WebAccess } from '../remember';
import { profileResetEvent } from '../ui/profile-reset';
import { ArtifactSessionSecrets } from './artifact-secrets';

export const ArtifactSecretsContext = createContext<ArtifactSessionSecrets | null>(null);

export function useTabArtifactSecrets(
    access: WebAccess,
    signal?: AbortSignal,
): ArtifactSessionSecrets {
    const [cache, setCache] = useState(() => new ArtifactSessionSecrets(access));
    const previous = useRef(cache);
    useLayoutEffect(() => {
        // Each effect setup gets a fresh lifetime. StrictMode replay may retire its
        // previous instance, but can never resurrect it for a late worker write.
        previous.current.retire();
        const created = new ArtifactSessionSecrets(access);
        previous.current = created;
        setCache(created);
        const retire = () => created.retire();
        const unsubscribe = access.subscribeStatus(() => {
            if (access.status() === 'closed') {
                retire();
            }
        });
        signal?.addEventListener('abort', retire, { once: true });
        window.addEventListener(profileResetEvent, retire);
        if (signal?.aborted || access.status() === 'closed') {
            retire();
        }
        return () => {
            signal?.removeEventListener('abort', retire);
            window.removeEventListener(profileResetEvent, retire);
            unsubscribe();
            retire();
        };
    }, [access, signal]);
    return cache;
}

export function useArtifactSecrets(access: WebAccess): ArtifactSessionSecrets {
    const shared = useContext(ArtifactSecretsContext);
    const own = useTabArtifactSecrets(access);
    return shared ?? own;
}
