import { useCallback, useEffect, useId, useRef, useState } from 'react';
import type { ReadProgress as Progress } from '../management/progress';
import type { RecordingSourceImages } from '../management/source-transfer';
import type { WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import type { GridWork } from '../ui/GridWork';
import { Modal } from '../ui/material';
import { t } from '../ui/messages';
import { readLocalBytes } from '../wasm/local-file';
import { EvidenceError } from './evidence-protocol';
import {
  type LocalRecordingIndex,
  RecordingIndexBuilder,
  recordingByteDigest,
} from './recording-index';
import { useArtifactSecrets } from './session-secrets';
import { VerificationDialog } from './VerificationDialog';
import { LocalKeyFields, VerificationFields, validSigningID } from './VerificationFields';
import {
  createRecordingVerificationBatch,
  type EvidenceKey,
  type RecordingVerificationBatch,
} from './verify';

export function useRecordingVerification({
  access,
  source,
  producerId = '',
  active,
  disabled,
}: {
  access: WebAccess;
  source: string;
  producerId?: string;
  active: boolean;
  disabled: boolean;
}) {
  const secrets = useArtifactSecrets(access);
  const controller = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const owner = useRef({ access, source });
  owner.current = { access, source };
  const [stateOwner, setStateOwner] = useState({ access, source });
  const ownedState = stateOwner.access === access && stateOwner.source === source;
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [result, setResult] = useState<{
    checked: number;
    full: number;
    outer: number;
    producer: string;
    reported: boolean;
    metadataLimited: boolean;
  } | null>(null);
  const [failed, setFailed] = useState('');
  const [localIndex, setLocalIndex] = useState<LocalRecordingIndex | null>(null);
  const [revealIndex, setRevealIndex] = useState<LocalRecordingIndex | null>(null);
  const revealWanted = useRef(false);
  const [used, setUsed] = useState<{ producer: string; reported: boolean } | null>(null);
  const [optionsOpen, setOptionsOpen] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [level, setLevel] = useState<'outer' | 'private'>('private');
  const [producer, setProducer] = useState('');
  const [checked, setChecked] = useState(false);
  const [reported, setReported] = useState(true);
  const seeded = useRef('');
  const file = useRef<HTMLInputElement>(null);
  const form = useRef<HTMLFormElement>(null);
  const [candidate, setCandidate] = useState(false);
  const [revision, setRevision] = useState(0);
  const inputID = useId();
  const passwordID = useId();
  const clearInputs = useCallback(() => {
    if (file.current) {
      file.current.value = '';
    }
    const password = form.current?.querySelector<HTMLInputElement>('[name="evidence-passphrase"]');
    if (password) {
      password.value = '';
    }
    setCandidate(false);
    setRevision((value) => value + 1);
  }, []);
  // biome-ignore lint/correctness/useExhaustiveDependencies: Actor/source boundaries retire the entire owned job, never resume a previous source.
  useEffect(() => {
    generation.current++;
    setBusy(false);
    setProgress(null);
    setResult(null);
    setFailed('');
    setLocalIndex(null);
    setRevealIndex(null);
    revealWanted.current = false;
    setUsed(null);
    setOptionsOpen(false);
    setDetailsOpen(false);
    setLevel('private');
    setProducer('');
    setChecked(false);
    setReported(true);
    seeded.current = '';
    clearInputs();
    setStateOwner({ access, source });
    return () => {
      generation.current++;
      controller.current?.abort();
      controller.current = null;
    };
  }, [access, source]);
  useEffect(() => {
    if (owner.current.access !== access || owner.current.source !== source) {
      return;
    }
    if (reported && validSigningID(producerId) && seeded.current !== producerId) {
      seeded.current = producerId;
      setProducer(producerId);
      setChecked(true);
    }
  }, [producerId, reported, access, source]);
  useEffect(() => {
    if (!active || disabled) {
      controller.current?.abort();
      revealWanted.current = false;
      setOptionsOpen(false);
      clearInputs();
    }
  }, [active, disabled, clearInputs]);

  async function verify() {
    if (
      !ownedState ||
      !active ||
      disabled ||
      !source ||
      controller.current ||
      (checked && !validSigningID(producer))
    ) {
      return;
    }
    const stopped = new AbortController();
    const token = ++generation.current;
    controller.current = stopped;
    setBusy(true);
    setUsed({ producer: checked ? producer : '', reported });
    setLocalIndex(null);
    setRevealIndex(null);
    setFailed('');
    setResult(null);
    setProgress(null);
    const selectedKey = file.current?.files?.[0];
    const password =
      form.current?.querySelector<HTMLInputElement>('[name="evidence-passphrase"]')?.value ?? '';
    const owned = () =>
      token === generation.current &&
      owner.current.access === access &&
      owner.current.source === source &&
      access.status() !== 'closed';
    let batch: RecordingVerificationBatch | undefined;
    let stream: RecordingSourceImages | undefined;
    let builder = level === 'private' ? new RecordingIndexBuilder(source, reported) : null;
    try {
      let chosen: EvidenceKey | null = null;
      if (selectedKey) {
        if (selectedKey.size < 1 || selectedKey.size > 64 << 10) {
          throw new EvidenceError('key');
        }
        const bytes = await readLocalBytes(selectedKey, stopped.signal);
        try {
          chosen = { file: new Blob([bytes]), passphrase: password };
        } finally {
          new Uint8Array(bytes).fill(0);
        }
      }
      const completed = {
        checked: 0,
        full: 0,
        outer: 0,
        producer: checked ? producer : '',
        reported,
        metadataLimited: false,
      };
      stream = await access.openRecordingSource(source, stopped.signal, (value) => {
        if (owned() && !stopped.signal.aborted) {
          setProgress(value);
        }
      });
      for await (const row of stream) {
        if (stopped.signal.aborted || !owned()) {
          throw new EvidenceError('cancelled');
        }
        if (row.request.kind !== 'recording' || row.request.auditlog !== source) {
          throw new EvidenceError('input');
        }
        batch ??= await createRecordingVerificationBatch(source, stopped.signal);
        if (!owned() || stopped.signal.aborted) {
          throw new EvidenceError('cancelled');
        }
        const image = await batch.receive(row.request, row.image);
        if (!owned() || stopped.signal.aborted) {
          throw new EvidenceError('cancelled');
        }
        const key =
          level === 'private' && row.encrypted ? (chosen ?? secrets.matching(row.recipient)) : null;
        if (level === 'private' && row.encrypted && !key) {
          throw new EvidenceError('key-required');
        }
        if (!owned() || stopped.signal.aborted) {
          throw new EvidenceError('cancelled');
        }
        const verified = await batch.verify(
          image,
          {
            producer: checked ? producer : '',
            allowUntrusted: !checked,
            recipient: level === 'outer' ? row.recipient : '',
            ...(key ? { recipientFromKey: true } : {}),
            level,
            export: false,
            sensitive: false,
            auditScope: '',
            ...(builder ? { metadata: true } : {}),
          },
          key,
          (value) => {
            if (owned() && !stopped.signal.aborted) {
              setProgress(value);
            }
          },
        );
        if (!owned() || stopped.signal.aborted) {
          throw new EvidenceError('cancelled');
        }
        if (key) {
          secrets.remember(key, verified);
        }
        try {
          if (builder) {
            const digest = await recordingByteDigest(image, stopped.signal);
            if (!owned() || stopped.signal.aborted) {
              throw new EvidenceError('cancelled');
            }
            builder.add(image, verified, digest);
          }
        } catch (error) {
          if (!(error instanceof EvidenceError && error.code === 'limit')) {
            throw error;
          }
          // The additional display index is bounded; the confirmed source
          // verification itself must still finish every recording as before.
          builder?.clear();
          builder = null;
          completed.metadataLimited = true;
        }
        completed.checked++;
        if (verified.metadata.validation === 'private') {
          completed.full++;
        } else {
          completed.outer++;
        }
        if (owned()) {
          setProgress({
            phase: 'verifying',
            completed: completed.checked,
            total: row.total,
          });
        }
      }
      if (owned() && !stopped.signal.aborted) {
        const index = builder?.finish() ?? null;
        setLocalIndex(index);
        setRevealIndex(revealWanted.current ? index : null);
        setResult(completed);
      }
    } catch (error) {
      if (owned() && !stopped.signal.aborted) {
        setFailed(
          error instanceof EvidenceError || error instanceof RememberMeError
            ? error.code
            : 'unavailable',
        );
      }
    } finally {
      builder?.clear();
      revealWanted.current = false;
      batch?.dispose();
      await stream?.return?.();
      if (owned()) {
        clearInputs();
      }
      if (controller.current === stopped) {
        controller.current = null;
      }
      if (owned()) {
        setBusy(false);
      }
    }
  }
  const work: GridWork = {
    mode: ownedState && busy ? 'cancel' : ownedState && (result || failed) ? 'server' : 'verify',
    disabled: disabled || !active || !source || !ownedState,
    progress: ownedState ? progress : null,
    result: ownedState ? (result ? 'success' : failed ? 'failure' : undefined) : undefined,
    onStatusClick: () => setDetailsOpen(true),
    onClick: () => {
      if (busy) {
        controller.current?.abort();
      } else if (result || failed) {
        setResult(null);
        setFailed('');
        setLocalIndex(null);
        setRevealIndex(null);
        revealWanted.current = false;
        setUsed(null);
        setDetailsOpen(false);
      } else {
        revealWanted.current = false;
        clearInputs();
        setOptionsOpen(true);
      }
    },
  };
  const dialog = (
    <>
      <VerificationDialog
        open={optionsOpen && active && !disabled && ownedState}
        source={source}
        kind="recordings"
        disabled={busy || !source || (checked && !validSigningID(producer))}
        onClose={() => {
          revealWanted.current = false;
          setOptionsOpen(false);
          clearInputs();
        }}
        onStart={() => {
          setOptionsOpen(false);
          void verify();
        }}
      >
        <VerificationFields
          level={level}
          onLevel={(value) => {
            setLevel(value);
            clearInputs();
          }}
          checked={checked}
          onChecked={setChecked}
          producer={producer}
          onProducer={(value) => {
            setProducer(value);
            setReported(false);
          }}
          reported={reported}
          disabled={busy}
        >
          <LocalKeyFields
            input={file}
            form={form}
            id={inputID}
            passwordID={passwordID}
            revision={revision}
            candidate={candidate}
            onCandidate={setCandidate}
            disabled={busy}
            cached={secrets.fingerprint() !== null}
          />
        </VerificationFields>
      </VerificationDialog>
      <Modal
        opened={detailsOpen && active && !disabled && ownedState}
        onClose={() => setDetailsOpen(false)}
        title={t('recordingVerificationDetails')}
      >
        <dl className="metadata-grid">
          <dt>{t('verifyAllSource')}</dt>
          <dd>{source}</dd>
          <dt>{t('auditEventOutcome')}</dt>
          <dd>{t(failed ? 'artifactVerificationError' : 'verificationCompleted')}</dd>
          <dt>{t('artifactDiagnosticCode')}</dt>
          <dd>{failed || (result?.metadataLimited ? 'metadata-limit' : '—')}</dd>
          {result?.metadataLimited && (
            <>
              <dt>{t('detailsTitle')}</dt>
              <dd>{t('recordingMetadataIndexLimit')}</dd>
            </>
          )}
          <dt>{t('verificationCheckedRecordings')}</dt>
          <dd>{result?.checked ?? '—'}</dd>
          <dt>{t('verifyAllFull')}</dt>
          <dd>{result?.full ?? '—'}</dd>
          <dt>{t('verifyAllOuter')}</dt>
          <dd>{result?.outer ?? '—'}</dd>
          <dt>{t('artifactExpectedProducer')}</dt>
          <dd>{used?.producer || t('artifactSignerNotPinned')}</dd>
          <dt>{t('artifactTrust')}</dt>
          <dd>
            {t(
              !used?.producer
                ? 'artifactSignerNotPinned'
                : used.reported
                  ? 'artifactServerSigner'
                  : result
                    ? 'artifactUserSelectedSigner'
                    : 'verificationMatchNotEstablished',
            )}
          </dd>
        </dl>
      </Modal>
    </>
  );
  return {
    work,
    dialog,
    localIndex: ownedState ? localIndex : null,
    revealIndex: ownedState ? revealIndex : null,
    openPrivate: () => {
      if (active && !disabled && !busy) {
        revealWanted.current = true;
        setLevel('private');
        clearInputs();
        setOptionsOpen(true);
      }
    },
  };
}
