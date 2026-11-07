import { useCallback, useSyncExternalStore } from 'react';
import type { AccessStatus, WebAccess } from '../remember/client';

// Observe only tab-memory state and the web-grant deadline. Never probe the
// server, inspect saved credentials or turn an expired grant into a new actor.
export function useAccessStatus(access: WebAccess, management = false): AccessStatus {
  const subscribe = useCallback(
    (changed: () => void) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const check = () => {
        clearTimeout(timer);
        changed();
        if (access.status() === 'active') {
          timer = setTimeout(
            check,
            Math.min(
              Math.max(Date.parse(access.snapshot().expiresAt) - Date.now(), 1),
              2_147_483_647,
            ),
          );
        }
      };
      const unsubscribe = access.subscribeStatus(check);
      window.addEventListener('focus', check);
      document.addEventListener('visibilitychange', check);
      check();
      return () => {
        clearTimeout(timer);
        unsubscribe();
        window.removeEventListener('focus', check);
        document.removeEventListener('visibilitychange', check);
      };
    },
    [access],
  );
  const snapshot = useCallback(
    () => (management ? access.managementStatus() : access.status()),
    [access, management],
  );
  return useSyncExternalStore(subscribe, snapshot, snapshot);
}
