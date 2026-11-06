import { useEffect, useEffectEvent, useRef, useSyncExternalStore } from 'react';
import { reportUiError } from './error-report';
import { profilePreferencesResetEvent } from './profile-reset';

// Presentation only: never a credential, permission, decryption or trust flag.
// localStorage is origin-bound; no account names or artifact selectors are saved.
export const detailPreferenceKey = 'bifroest-ui-v1:details';
const changedEvent = 'bifroest-details-preference';
let volatileOverride: boolean | null = null;
function snapshot(): boolean {
  if (volatileOverride !== null) {
    return volatileOverride;
  }
  try {
    return localStorage.getItem(detailPreferenceKey) !== 'compact';
  } catch {
    return true;
  }
}
function subscribe(changed: () => void): () => void {
  const storage = (event: StorageEvent) => {
    if (event.key === detailPreferenceKey || event.key === null) {
      volatileOverride = null;
      changed();
    }
  };
  window.addEventListener('storage', storage);
  window.addEventListener(changedEvent, changed);
  const reset = () => {
    volatileOverride = null;
    changed();
  };
  window.addEventListener(profilePreferencesResetEvent, reset);
  return () => {
    window.removeEventListener('storage', storage);
    window.removeEventListener(changedEvent, changed);
    window.removeEventListener(profilePreferencesResetEvent, reset);
  };
}
export function setDetailedView(value: boolean): void {
  try {
    localStorage.setItem(detailPreferenceKey, value ? 'full' : 'compact');
    volatileOverride = null;
  } catch (error) {
    volatileOverride = value;
    reportUiError('preferences', error);
  }
  window.dispatchEvent(new Event(changedEvent));
}
export function useDetailedView(): boolean {
  return useSyncExternalStore(subscribe, snapshot, () => true);
}
// Queue preference changes while inactive/busy. Refresh exactly once when the
// owning view is usable again, not in every hidden management page.
export function useDetailRefresh(
  active: boolean,
  disabled: boolean,
  busy: boolean,
  refresh: () => void,
): boolean {
  const detailed = useDetailedView();
  const applied = useRef(detailed);
  const reload = useEffectEvent(refresh);
  useEffect(() => {
    if (active && !disabled && !busy && applied.current !== detailed) {
      applied.current = detailed;
      reload();
    }
  }, [active, disabled, busy, detailed]);
  return detailed;
}
