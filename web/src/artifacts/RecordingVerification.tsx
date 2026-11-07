import { useEffect, useRef, useState } from 'react';
import type { CatalogVerification } from '../management/audit-overview';
import type { ReadProgress as Progress } from '../management/progress';
import type { WebAccess } from '../remember';
import type { GridWork } from '../ui/GridWork';
import { t } from '../ui/messages';
import { VerificationDialog } from './VerificationDialog';

export function useRecordingVerification({
  access,
  source,
  active,
  disabled,
}: {
  access: WebAccess;
  source: string;
  active: boolean;
  disabled: boolean;
}) {
  const controller = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const owner = useRef({ access, source });
  owner.current = { access, source };
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [result, setResult] = useState<CatalogVerification | null>(null);
  const [failed, setFailed] = useState(false);
  const [cancelled, setCancelled] = useState(false);
  const [optionsOpen, setOptionsOpen] = useState(false);
  // biome-ignore lint/correctness/useExhaustiveDependencies: Reset the entire explicit job at its actor/source boundary, never replay it after navigation.
  useEffect(() => {
    generation.current++;
    setBusy(false);
    setProgress(null);
    setResult(null);
    setFailed(false);
    setCancelled(false);
    setOptionsOpen(false);
    return () => {
      generation.current++;
      controller.current?.abort();
      controller.current = null;
    };
  }, [access, source]);
  useEffect(() => {
    if (!active || disabled) {
      controller.current?.abort();
    }
  }, [active, disabled]);
  async function verify(selected: string) {
    if (!active || disabled || selected !== source || controller.current !== null) {
      return;
    }
    const stopped = new AbortController();
    const token = ++generation.current;
    controller.current = stopped;
    setBusy(true);
    setFailed(false);
    setCancelled(false);
    setResult(null);
    setProgress(null);
    const owned = () =>
      token === generation.current &&
      owner.current.access === access &&
      owner.current.source === source;
    try {
      const checked = await access.managementVerifyRecordings(selected, stopped.signal, (value) => {
        if (owned() && !stopped.signal.aborted) {
          setProgress(value);
        }
      });
      if (owned() && !stopped.signal.aborted) {
        setResult(checked);
      }
    } catch {
      if (owned()) {
        setCancelled(stopped.signal.aborted);
        setFailed(!stopped.signal.aborted);
      }
    } finally {
      if (controller.current === stopped) {
        controller.current = null;
      }
      if (owned()) {
        setBusy(false);
      }
    }
  }
  const work: GridWork = {
    mode: busy ? 'cancel' : 'verify',
    disabled: disabled || !active || source === '',
    progress,
    onClick: () => (busy ? controller.current?.abort() : setOptionsOpen(true)),
    status: failed
      ? t('verifyAllServerFailed')
      : cancelled
        ? t('verifyAllServerCancelled')
        : result
          ? `${t('verifyAllServerDone')} ${result.checked} (${t('verifyAllFull')}: ${result.full}; ${t('verifyAllOuter')}: ${result.outer})`
          : undefined,
  };
  const dialog = (
    <VerificationDialog
      open={optionsOpen && active && !disabled}
      source={source}
      kind="recordings"
      disabled={busy || source === ''}
      onClose={() => setOptionsOpen(false)}
      onStart={() => {
        setOptionsOpen(false);
        void verify(source);
      }}
    />
  );
  return { work, dialog };
}
