import {
    createContext,
    type ReactNode,
    useContext,
    useLayoutEffect,
    useRef,
    useState,
    useSyncExternalStore,
} from 'react';
import type { WebAccess } from '../remember';
import { profileResetEvent } from '../ui/profile-reset';
import { useOwnerKey } from '../ui/use-owner-key';
import { ArtifactSessionSecrets } from './artifact-secrets';
import { EvidenceError } from './evidence-protocol';

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
    if (!shared?.ownedBy(access)) {
        throw new EvidenceError('cancelled');
    }
    // Only fingerprint/revision metadata crosses the React subscription. Key
    // bytes and passphrases remain private to this owner-bound service.
    useSyncExternalStore(shared.subscribe, shared.getSnapshot);
    return shared;
}

function StandaloneSecrets({ access, children }: { access: WebAccess; children?: ReactNode }) {
    const cache = useTabArtifactSecrets(access);
    return (
        <ArtifactSecretsContext.Provider value={cache}>{children}</ArtifactSecretsContext.Provider>
    );
}

// Integrated views reuse their tab's cache. Only a genuinely standalone view
// mounts a cache provider; consumers never create unused fallback services.
export function ArtifactSecretsBoundary({
    access,
    children,
}: {
    access: WebAccess;
    children?: ReactNode;
}) {
    const shared = useContext(ArtifactSecretsContext);
    const ownerKey = useOwnerKey(access);
    if (shared?.ownedBy(access)) {
        return children;
    }
    return (
        <StandaloneSecrets key={ownerKey} access={access}>
            {children}
        </StandaloneSecrets>
    );
}
