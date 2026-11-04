import { useEffect, useId, useRef, useState } from 'react';
import type { RecordingSummary } from '../management/protocol';
import type { WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { AdminBreadcrumbs } from '../ui/AdminBreadcrumbs';
import { useAdminDetail } from '../ui/admin-navigation';
import { reportUiError } from '../ui/error-report';
import {
  Alert,
  Button,
  Checkbox,
  Paper,
  PasswordInput,
  Radio,
  Select,
  TextInput,
  Title,
} from '../ui/material';
import type { Message } from '../ui/messages';
import { t } from '../ui/messages';
import { ArtifactCatalog } from './ArtifactCatalog';
import { ArtifactSourceDetails } from './ArtifactSourceDetails';
import type { EvidenceOptions, VerifiedArtifact } from './evidence-protocol';
import { EvidenceError, evidenceOptions } from './evidence-protocol';
import { LocalArtifactDownload } from './local-download';
import type { ArtifactRequest, ReceivedArtifact } from './protocol';
import { artifactFields } from './protocol';
import { RecordingPlayer } from './RecordingPlayer';
import type { EvidenceKey } from './verify';
import { verifyArtifact } from './verify';

function failure(error: unknown): Message {
  if (error instanceof EvidenceError) {
    return error.code === 'key'
      ? 'artifactKeyFailed'
      : error.code === 'verification'
        ? 'artifactVerificationFailed'
        : error.code === 'limit'
          ? 'artifactLimit'
          : error.code === 'input'
            ? 'artifactInputFailed'
            : error.code === 'cancelled'
              ? 'artifactCancelled'
              : 'artifactUnavailable';
  }
  return error instanceof RememberMeError && error.code === 'artifact-too-large'
    ? 'artifactLimit'
    : error instanceof RememberMeError && error.code === 'cancelled'
      ? 'artifactCancelled'
      : error instanceof RememberMeError && error.code === 'denied'
        ? 'artifactDownloadDenied'
        : 'artifactDownloadFailed';
}

export function ArtifactPanel({
  access,
  disabled,
  remoteDisabled = false,
  active = true,
}: {
  access: WebAccess;
  disabled: boolean;
  remoteDisabled?: boolean;
  active?: boolean;
}) {
  const keyInputID = useId();
  const passphraseInputID = useId();
  const [kind, setKind] = useState<'recording' | 'audit'>('recording');
  const [auditlog, setAuditlog] = useState('');
  const [id, setID] = useState('');
  const [received, setReceived] = useState<ReceivedArtifact | null>(null);
  const [filePage, setFilePage] = useState(0);
  const [verified, setVerified] = useState<VerifiedArtifact | null>(null);
  const [producer, setProducer] = useState('');
  const [untrusted, setUntrusted] = useState(false);
  const [encryption, setEncryption] = useState('');
  const [recipient, setRecipient] = useState('');
  const [level, setLevel] = useState<'outer' | 'private'>('private');
  const [scope, setScope] = useState<'complete' | 'captured-prefix'>('complete');
  const [exporting, setExporting] = useState(true);
  const [sensitive, setSensitive] = useState(false);
  const [phase, setPhase] = useState<'downloading' | 'verifying' | null>(null);
  const [notice, setNotice] = useState<Message | null>(null);
  const [keyRevision, setKeyRevision] = useState(0);
  const [selectionOpen, setSelectionOpen] = useState(true);
  const [manualOpen, setManualOpen] = useState(false);
  const [opened, setOpened] = useState<ArtifactRequest | null>(null);
  const [chosen, setChosen] = useState<ArtifactRequest | null>(null);
  const [selection, setSelection] = useState<RecordingSummary | null>(null);
  const [keyPresent, setKeyPresent] = useState(false);
  const heading = useRef<HTMLHeadingElement | null>(null);
  const wasActive = useRef(active);
  wasActive.current = active;
  const form = useRef<HTMLFormElement | null>(null);
  const operation = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const downloads = useRef(new LocalArtifactDownload());
  const returningToCatalog = useRef(false);

  function closeRecording() {
    returningToCatalog.current = true;
    setReceived(null);
    setOpened(null);
    setSelection(null);
    setSelectionOpen(true);
    invalidateResult();
  }
  useEffect(() => {
    if (selectionOpen && returningToCatalog.current) {
      returningToCatalog.current = false;
      if (wasActive.current) {
        heading.current?.focus();
        heading.current?.scrollIntoView({ block: 'nearest' });
      }
    }
  }, [selectionOpen]);

  function clearKey() {
    for (const selector of ['[name="evidence-private"]', '[name="evidence-passphrase"]']) {
      const input = form.current?.querySelector<HTMLInputElement>(selector);
      if (input) {
        input.value = '';
      }
    }
    setKeyRevision((value) => value + 1); // Reset Mantine's uncontrolled internal state too.
    setKeyPresent(false);
  }

  function invalidateResult() {
    downloads.current.clear();
    setVerified(null);
    setNotice(null);
    clearKey();
  }

  function selectionChanged() {
    setReceived(null);
    setProducer('');
    setUntrusted(false);
    setEncryption('');
    setRecipient('');
    setLevel('private');
    setScope('complete');
    setExporting(true);
    setSensitive(false);
    invalidateResult();
  }

  // Every actor/disabled transition retires local secrets, plaintext and workers.
  // The parent also keys this panel by its authentication generation.
  // biome-ignore lint/correctness/useExhaustiveDependencies: Explicit actor/availability boundary; no application operation is resumed by this effect.
  useEffect(() => {
    generation.current++;
    operation.current?.abort();
    operation.current = null;
    downloads.current.clear();
    setReceived(null);
    setVerified(null);
    setPhase(null);
    setNotice(null);
    setOpened(null);
    setChosen(null);
    setSelection(null);
    setSelectionOpen(true);
    setProducer('');
    setUntrusted(false);
    setEncryption('');
    setRecipient('');
    setLevel('private');
    setScope('complete');
    setExporting(true);
    setSensitive(false);
    clearKey();
    return () => {
      generation.current++;
      operation.current?.abort();
      operation.current = null;
      downloads.current.clear();
      for (const selector of ['[name="evidence-private"]', '[name="evidence-passphrase"]']) {
        const input = form.current?.querySelector<HTMLInputElement>(selector);
        if (input) {
          input.value = '';
        }
      }
    };
  }, [access, disabled]);
  useEffect(() => {
    if (remoteDisabled && phase === 'downloading') {
      generation.current++;
      operation.current?.abort();
      setNotice('artifactCancelled');
    }
  }, [remoteDisabled, phase]);

  async function run(
    next: 'downloading' | 'verifying',
    action: (signal: AbortSignal, current: number) => Promise<void>,
  ) {
    if (disabled || operation.current !== null) {
      return;
    }
    const controller = new AbortController();
    const current = ++generation.current;
    operation.current = controller;
    setPhase(next);
    downloads.current.clear();
    setVerified(null);
    setNotice(null);
    try {
      await action(controller.signal, current);
    } catch (error) {
      if (current === generation.current) {
        reportUiError('artifact', error);
        setNotice(failure(error));
      }
    } finally {
      if (operation.current === controller) {
        operation.current = null;
        setPhase(null);
      }
    }
  }

  function cancel() {
    // Keep the slot until joined cleanup completes, so cancellation cannot start
    // a competing download or display a late result from the previous worker.
    generation.current++;
    const pending = operation.current;
    pending?.abort();
    downloads.current.clear();
    setVerified(null);
    clearKey();
    setNotice('artifactCancelled');
  }

  async function download(request?: ArtifactRequest, summary?: RecordingSummary) {
    if (disabled || remoteDisabled || operation.current !== null) {
      return;
    }
    const selected: ArtifactRequest =
      request ?? (kind === 'recording' ? { kind, auditlog, id } : { kind, auditlog });
    selectionChanged();
    setKind(selected.kind);
    setAuditlog(selected.auditlog);
    setID(selected.kind === 'recording' ? selected.id : '');
    setOpened(selected);
    setChosen(selected);
    setSelection(summary ?? null);
    setSelectionOpen(false);
    clearKey();
    await run('downloading', async (signal, current) => {
      setReceived(null);
      setFilePage(0);
      try {
        artifactFields(selected);
      } catch {
        throw new EvidenceError('input');
      }
      const result = await access.downloadArtifact(selected, signal);
      if (current === generation.current && !signal.aborted) {
        setReceived(result);
        setSelectionOpen(false);
        if (wasActive.current) {
          heading.current?.focus();
        }
      }
    });
  }

  async function verify() {
    const selected = received;
    if (selected === null || disabled || operation.current !== null) {
      return;
    }
    let key: EvidenceKey | null = null;
    const file = form.current?.querySelector<HTMLInputElement>('[name="evidence-private"]')
      ?.files?.[0];
    const password =
      form.current?.querySelector<HTMLInputElement>('[name="evidence-passphrase"]')?.value ?? '';
    if (file !== undefined) {
      key = { file, passphrase: password };
    }
    clearKey();
    try {
      await run('verifying', async (signal, current) => {
        if (
          encryption === '' ||
          (level === 'private' && encryption === 'encrypted' && key === null) ||
          (!file && password !== '')
        ) {
          throw new EvidenceError('input');
        }
        const options: EvidenceOptions = evidenceOptions(selected.request, {
          producer: untrusted ? '' : producer,
          allowUntrusted: untrusted,
          recipient: encryption === 'encrypted' ? recipient : '',
          level,
          export: level === 'private' && exporting,
          sensitive: selected.request.kind === 'audit' && level === 'private' && sensitive,
          auditScope: selected.request.kind === 'audit' ? scope : '',
        });
        const result = await verifyArtifact(selected, options, key, signal);
        if (current === generation.current && !signal.aborted) {
          setVerified(result);
        }
      });
    } finally {
      key = null;
    }
  }

  function save(data: Blob, filename: string) {
    if (disabled || operation.current !== null) {
      return;
    }
    try {
      downloads.current.save(data, filename);
    } catch (error) {
      reportUiError('artifact-save', error);
      setNotice('artifactSaveFailed');
    }
  }

  const locked = disabled || phase !== null;
  const downloadLocked = locked || remoteDisabled;
  const metadata = verified?.metadata;
  const pinReady = untrusted || (/^[0-9a-f]{64}$/u.test(producer) && !/^0+$/u.test(producer));
  const protectionReady =
    encryption === 'clear' ||
    (encryption === 'encrypted' && /^SHA256:[A-Za-z0-9+/]{43}$/u.test(recipient));
  const keyReady = level !== 'private' || encryption !== 'encrypted' || keyPresent;
  const verificationReady = pinReady && protectionReady && keyReady;
  const integratedNavigation = useAdminDetail(
    'artifacts',
    opened !== null && !selectionOpen
      ? opened.kind === 'recording'
        ? opened.id
        : opened.auditlog
      : null,
    closeRecording,
  );
  return (
    <Paper
      withBorder
      p="lg"
      className="stack artifact-panel"
      component="section"
      aria-label={t('artifactTitle')}
    >
      {!integratedNavigation && (
        <AdminBreadcrumbs
          items={[
            { label: t('workspaceBifroest') },
            {
              label: t('artifactTitle'),
              ...(opened !== null && !selectionOpen
                ? { onClick: closeRecording, disabled: locked }
                : {}),
            },
            ...(opened !== null && !selectionOpen
              ? [
                  {
                    label: opened.kind === 'recording' ? opened.id : opened.auditlog,
                  },
                ]
              : []),
          ]}
        />
      )}
      <div className="section-heading">
        <h2 ref={heading} tabIndex={-1} className="recording-heading">
          {t(
            opened === null || selectionOpen
              ? 'artifactTitle'
              : opened.kind === 'recording'
                ? 'recordingSelected'
                : 'recordingAuditExports',
          )}
        </h2>
      </div>
      {opened !== null && !selectionOpen && (
        <div className="recording-summary">
          <strong>
            {selection
              ? selection.user || selection.flow || t('recordingSelected')
              : opened.auditlog}
          </strong>
          {selection && (
            <span className="caption subtle">
              {selection.target ? `→ ${selection.target} · ` : ''}
              {selection.user && selection.flow ? `${selection.flow} · ` : ''}
              {new Intl.DateTimeFormat(undefined, {
                dateStyle: 'medium',
                timeStyle: 'short',
              }).format(new Date(selection.startedAt))}
            </span>
          )}
          <details className="context-help">
            <summary>{t('recordingDetails')}</summary>
            <p className="identifier">
              {opened.auditlog}
              {opened.kind === 'recording' ? ` / ${opened.id}` : ''}
            </p>
            <p>{t('recordingServerMetadata')}</p>
          </details>
        </div>
      )}
      <section className="artifact-selection" hidden={!selectionOpen}>
        <div className="artifact-selection-grid">
          <ArtifactCatalog
            access={access}
            disabled={downloadLocked}
            active={active && selectionOpen}
            selected={chosen}
            onSelect={(request, summary) => {
              void download(request, summary);
            }}
          />
          <details open={manualOpen} onToggle={(event) => setManualOpen(event.currentTarget.open)}>
            <summary>{t('recordingManual')}</summary>
            <p className="caption subtle">{t('artifactExplicitDownload')}</p>
            <form
              method="dialog"
              className="stack"
              onSubmit={(event) => {
                event.preventDefault();
                void download();
              }}
            >
              <Select
                label={t('artifactKind')}
                value={kind}
                disabled={downloadLocked}
                data={[
                  { value: 'recording', label: t('artifactRecording') },
                  { value: 'audit', label: t('artifactAudit') },
                ]}
                onChange={(value) => {
                  if (value === 'recording' || value === 'audit') {
                    setKind(value);
                    selectionChanged();
                  }
                }}
              />
              <TextInput
                label={t('artifactAuditlog')}
                value={auditlog}
                required
                maxLength={128}
                disabled={downloadLocked}
                onChange={(event) => {
                  setAuditlog(event.currentTarget.value);
                  selectionChanged();
                }}
              />
              {kind === 'recording' && (
                <TextInput
                  label={t('artifactRecordingID')}
                  value={id}
                  required
                  maxLength={36}
                  disabled={downloadLocked}
                  onChange={(event) => {
                    setID(event.currentTarget.value);
                    selectionChanged();
                  }}
                />
              )}
              <Button
                type="submit"
                disabled={downloadLocked || auditlog === '' || (kind === 'recording' && id === '')}
              >
                {t(kind === 'recording' ? 'recordingOpen' : 'recordingOpenAudit')}
              </Button>
            </form>
          </details>
        </div>
      </section>
      {notice !== null && (
        <Alert role="status" color={notice === 'artifactCancelled' ? 'yellow' : 'red'}>
          {t(notice)}
        </Alert>
      )}
      {notice !== null &&
        opened !== null &&
        received === null &&
        phase === null &&
        !selectionOpen && (
          <Button
            disabled={downloadLocked}
            onClick={() => {
              void download(opened, selection ?? undefined);
            }}
          >
            {t('recordingRetryOpen')}
          </Button>
        )}
      {phase !== null && (
        <div role="status" className="actions">
          <p>{t(phase === 'downloading' ? 'recordingOpening' : 'recordingVerifying')}</p>
          <Button variant="default" onClick={cancel}>
            {t('artifactCancel')}
          </Button>
        </div>
      )}
      {received !== null && (
        <>
          {verified === null && <p className="caption subtle">{t('recordingTrustIntroduction')}</p>}
          {verified === null && (
            <form
              ref={form}
              method="dialog"
              className="stack artifact-verification"
              onSubmit={(event) => {
                event.preventDefault();
                void verify();
              }}
            >
              <Title order={3}>{t('artifactExpectations')}</Title>
              <details className="context-help">
                <summary>{t('artifactTrustHelp')}</summary>
                <p>{t('artifactIndependentPins')}</p>
              </details>
              <Checkbox
                label={t('artifactAllowUntrusted')}
                checked={untrusted}
                disabled={locked}
                onChange={(event) => {
                  setUntrusted(event.currentTarget.checked);
                  invalidateResult();
                }}
              />
              {untrusted && <p className="caption subtle">{t('recordingTrustWithoutPin')}</p>}
              <TextInput
                label={t('artifactExpectedProducer')}
                value={producer}
                maxLength={64}
                required={!untrusted}
                disabled={locked || untrusted}
                autoComplete="off"
                onChange={(event) => {
                  setProducer(event.currentTarget.value);
                  invalidateResult();
                }}
              />
              {!untrusted && <p className="caption subtle">{t('recordingPinHelp')}</p>}
              <Select
                label={t('artifactEncryption')}
                value={encryption}
                required
                disabled={locked}
                placeholder={t('artifactChooseEncryption')}
                data={[
                  { value: 'clear', label: t('artifactClear') },
                  { value: 'encrypted', label: t('artifactEncrypted') },
                ]}
                onChange={(value) => {
                  setEncryption(value ?? '');
                  invalidateResult();
                }}
              />
              {encryption === 'encrypted' && (
                <TextInput
                  label={t('artifactExpectedRecipient')}
                  value={recipient}
                  required
                  maxLength={50}
                  disabled={locked}
                  autoComplete="off"
                  onChange={(event) => {
                    setRecipient(event.currentTarget.value);
                    invalidateResult();
                  }}
                />
              )}
              <details>
                <summary>{t('recordingAdvanced')}</summary>
                <div className="stack">
                  <Radio.Group
                    label={t('artifactPurpose')}
                    value={
                      level === 'private' && exporting
                        ? 'use'
                        : level === 'outer'
                          ? 'check'
                          : 'advanced'
                    }
                    onChange={(value) => {
                      setLevel(value === 'use' ? 'private' : 'outer');
                      setExporting(value === 'use');
                      invalidateResult();
                    }}
                  >
                    <div className="stack verification-purpose">
                      <Radio value="check" label={t('artifactPurposeCheck')} disabled={locked} />
                      <Radio
                        value="use"
                        label={t('artifactPurposeUse')}
                        description={t('artifactPurposeUseHint')}
                        disabled={locked}
                      />
                    </div>
                  </Radio.Group>
                  {level === 'private' && !exporting && (
                    <p className="caption subtle">{t('artifactCustomPurpose')}</p>
                  )}
                  <Select
                    label={t('artifactLevel')}
                    value={level}
                    disabled={locked}
                    data={[
                      { value: 'outer', label: t('artifactOuter') },
                      { value: 'private', label: t('artifactPrivate') },
                    ]}
                    onChange={(value) => {
                      setLevel(value === 'private' ? 'private' : 'outer');
                      invalidateResult();
                    }}
                  />
                  {kind === 'audit' && (
                    <Select
                      label={t('artifactAuditScope')}
                      value={scope}
                      disabled={locked}
                      data={[
                        { value: 'complete', label: t('artifactComplete') },
                        { value: 'captured-prefix', label: t('artifactPrefix') },
                      ]}
                      onChange={(value) => {
                        setScope(value === 'captured-prefix' ? 'captured-prefix' : 'complete');
                        invalidateResult();
                      }}
                    />
                  )}
                  {level === 'private' && (
                    <>
                      <Checkbox
                        label={t('artifactPrepareExport')}
                        checked={exporting}
                        disabled={locked}
                        onChange={(event) => {
                          setExporting(event.currentTarget.checked);
                          invalidateResult();
                        }}
                      />
                      {kind === 'audit' && (
                        <Checkbox
                          label={t('artifactSensitive')}
                          checked={sensitive}
                          disabled={locked}
                          onChange={(event) => {
                            setSensitive(event.currentTarget.checked);
                            invalidateResult();
                          }}
                        />
                      )}
                    </>
                  )}
                </div>
              </details>
              {level === 'private' && encryption === 'encrypted' && (
                <>
                  <Alert color="blue">{t('artifactKeyLocal')}</Alert>
                  <label className="stack" htmlFor={keyInputID}>
                    {t('artifactKeyFile')}
                    <input
                      key={`private:${keyRevision}`}
                      id={keyInputID}
                      name="evidence-private"
                      type="file"
                      required
                      disabled={locked}
                      onChange={(event) =>
                        setKeyPresent((event.currentTarget.files?.length ?? 0) > 0)
                      }
                    />
                  </label>
                  <PasswordInput
                    key={`passphrase:${keyRevision}`}
                    id={passphraseInputID}
                    name="evidence-passphrase"
                    label={t('artifactPassphrase')}
                    disabled={locked}
                    autoComplete="off"
                    visibilityToggleButtonProps={{ 'aria-label': t('togglePassword') }}
                  />
                </>
              )}
              {!verificationReady && (
                <p className="caption" role="status">
                  {t(keyReady ? 'recordingRequiredOptions' : 'recordingRequiredKey')}
                </p>
              )}
              <div className="artifact-actions">
                <Button type="submit" disabled={locked || !verificationReady}>
                  {t('artifactVerify')}
                </Button>
                <Button variant="default" disabled={locked} onClick={closeRecording}>
                  {t('artifactClearTab')}
                </Button>
              </div>
            </form>
          )}
          {verified === null && (
            <div className="stack recording-evidence">
              <ArtifactSourceDetails
                received={received}
                disabled={locked}
                page={filePage}
                onPage={setFilePage}
                onSave={save}
              />
            </div>
          )}
        </>
      )}
      {verified !== null && metadata !== undefined && (
        <section className="stack" aria-label={t('artifactResult')} aria-live="polite">
          <Alert color={metadata.trust === 'untrusted' ? 'yellow' : 'green'}>
            {t(
              metadata.trust === 'untrusted'
                ? 'recordingIdentityUnknown'
                : 'recordingIdentityPinned',
            )}
          </Alert>
          {verified.request.kind === 'recording' &&
            verified.output !== null &&
            metadata.validation === 'private' &&
            metadata.outputFormat === 'cast' && (
              <RecordingPlayer
                source={verified.output}
                expected={{
                  id: verified.request.id,
                  producer: untrusted ? '' : producer,
                  allowUntrusted: untrusted,
                }}
                disabled={locked}
                autoPrepare
                active={active}
              />
            )}
          <div className="artifact-actions">
            {verified.output !== null && (
              <Button
                variant="default"
                disabled={locked}
                onClick={() => {
                  if (verified.output !== null) {
                    save(
                      verified.output,
                      verified.request.kind === 'recording'
                        ? `recording-${verified.request.id}.cast`
                        : `audit-${verified.request.auditlog}.jsonl`,
                    );
                  }
                }}
              >
                {t('artifactSaveExport')}
              </Button>
            )}
            <Button variant="subtle" disabled={locked} onClick={invalidateResult}>
              {t('recordingChangeVerification')}
            </Button>
            <Button variant="default" disabled={locked} onClick={closeRecording}>
              {t('artifactClearTab')}
            </Button>
          </div>
          <section
            className="stack recording-evidence"
            aria-label={t('recordingVerificationDetails')}
          >
            <Title order={3}>{t('recordingVerificationDetails')}</Title>
            <dl className="metadata-grid">
              <dt>{t('artifactTrust')}</dt>
              <dd>
                {t(
                  metadata.trust === 'pinned' ? 'artifactPinnedResult' : 'artifactUntrustedResult',
                )}
              </dd>
              <dt>{t('artifactVerifiedProducer')}</dt>
              <dd>{metadata.producer}</dd>
              <dt>{t('artifactValidation')}</dt>
              <dd>{t(metadata.validation === 'private' ? 'artifactPrivate' : 'artifactOuter')}</dd>
              <dt>{t('artifactDecryption')}</dt>
              <dd>
                {t(
                  metadata.decryption === 'authenticated'
                    ? 'artifactDecrypted'
                    : metadata.decryption === 'no-private-records'
                      ? 'artifactNoPrivate'
                      : metadata.decryption === 'not-encrypted'
                        ? 'artifactNotEncrypted'
                        : 'artifactNotChecked',
                )}
              </dd>
              <dt>{t('artifactProvenance')}</dt>
              <dd>{t('artifactBytesOnly')}</dd>
              <dt>{t('artifactFreshness')}</dt>
              <dd>{t('artifactNotFresh')}</dd>
              {metadata.kind === 'audit' && (
                <>
                  <dt>{t('artifactExportFields')}</dt>
                  <dd>
                    {t(
                      verified.output === null
                        ? 'artifactNoExport'
                        : sensitive
                          ? 'artifactSensitiveFields'
                          : 'artifactRedactedFields',
                    )}
                  </dd>
                  <dt>{t('artifactAuditScope')}</dt>
                  <dd>
                    {t(
                      metadata.auditScope === 'captured-prefix'
                        ? 'artifactPrefix'
                        : 'artifactComplete',
                    )}
                  </dd>
                  <dt>{t('artifactRecordCount')}</dt>
                  <dd>{new Intl.NumberFormat('en-US').format(BigInt(metadata.records))}</dd>
                  <dt>{t('artifactPrivateCount')}</dt>
                  <dd>{new Intl.NumberFormat('en-US').format(BigInt(metadata.privateRecords))}</dd>
                </>
              )}
            </dl>
            {received !== null && (
              <>
                <hr />
                <ArtifactSourceDetails
                  received={received}
                  disabled={locked}
                  page={filePage}
                  onPage={setFilePage}
                  onSave={save}
                />
              </>
            )}
          </section>
        </section>
      )}
    </Paper>
  );
}
