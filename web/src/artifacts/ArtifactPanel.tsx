import CancelIcon from '@mui/icons-material/Cancel';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import { useEffect, useId, useRef, useState } from 'react';
import type { RecordingSummary } from '../management/protocol';
import type { WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { AdminBreadcrumbs } from '../ui/AdminBreadcrumbs';
import { useAdminDetail } from '../ui/admin-navigation';
import { reportUiError } from '../ui/error-report';
import { Alert, Button, Checkbox, Modal, PasswordInput, Select, TextInput } from '../ui/material';
import { type Message, t } from '../ui/messages';
import { readLocalBytes } from '../wasm/local-file';
import { ArtifactCatalog } from './ArtifactCatalog';
import { ArtifactSourceDetails } from './ArtifactSourceDetails';
import { AuditCatalog } from './AuditCatalog';
import { AuditEvents } from './AuditEvents';
import {
  EvidenceError,
  type EvidenceMetadata,
  evidenceOptions,
  type VerifiedArtifact,
} from './evidence-protocol';
import { LocalArtifactDownload } from './local-download';
import { inspectProtection } from './protection';
import { type ArtifactRequest, artifactFields, type ReceivedArtifact } from './protocol';
import { RecordingPlayer } from './RecordingPlayer';
import { useArtifactSecrets } from './session-secrets';
import { type EvidenceKey, verifyArtifact } from './verify';

type Phase = 'downloading' | 'inspecting' | 'verifying';
type UsedExpectation = { enabled: boolean; producer: string; source: 'reported' | 'user' };
function failure(error: unknown): Message {
  if (error instanceof EvidenceError) {
    return error.code === 'key'
      ? 'artifactKeyFailed'
      : error.code === 'verification'
        ? 'artifactVerificationFailed'
        : error.code === 'limit'
          ? 'artifactLimit'
          : error.code === 'cancelled'
            ? 'artifactCancelled'
            : error.code === 'input'
              ? 'artifactInputFailed'
              : 'artifactUnavailable';
  }
  return error instanceof RememberMeError && error.code === 'denied'
    ? 'artifactDownloadDenied'
    : error instanceof RememberMeError && error.code === 'cancelled'
      ? 'artifactCancelled'
      : 'artifactDownloadFailed';
}

// Both pages use the same actor-owned, volatile key cache, never each other's
// selection, workers, verification result or plaintext. No form uploads secrets.
export function ArtifactPanel({
  access,
  disabled,
  remoteDisabled = false,
  active = true,
  view = 'recordings',
}: {
  access: WebAccess;
  disabled: boolean;
  remoteDisabled?: boolean;
  active?: boolean;
  view?: 'recordings' | 'auditlogs';
}) {
  const secrets = useArtifactSecrets(access);
  const inputID = useId();
  const passwordID = useId();
  const [opened, setOpened] = useState<ArtifactRequest | null>(null);
  const [selection, setSelection] = useState<RecordingSummary | null>(null);
  const [received, setReceived] = useState<ReceivedArtifact | null>(null);
  const [protection, setProtection] = useState<EvidenceMetadata | null>(null);
  const [verified, setVerified] = useState<VerifiedArtifact | null>(null);
  const [phase, setPhase] = useState<Phase | null>(null);
  const [notice, setNotice] = useState<Message | null>(null);
  const [errorCode, setErrorCode] = useState('');
  const [failedStage, setFailedStage] = useState<Phase | null>(null);
  const [details, setDetails] = useState(false);
  const [filePage, setFilePage] = useState(0);
  const [candidate, setCandidate] = useState(false);
  const [keyRevision, setKeyRevision] = useState(0);
  const [cacheRevision, setCacheRevision] = useState(0);
  const [validateIdentity, setValidateIdentity] = useState(false);
  const [producer, setProducer] = useState('');
  const [producerSource, setProducerSource] = useState<'reported' | 'user'>('reported');
  const [used, setUsed] = useState<UsedExpectation | null>(null);
  const [sensitive, setSensitive] = useState(false);
  const [level, setLevel] = useState<'outer' | 'private'>('private');
  const [scope, setScope] = useState<'complete' | 'captured-prefix'>('complete');
  const [auditlog, setAuditlog] = useState('');
  const [id, setID] = useState('');
  const heading = useRef<HTMLHeadingElement | null>(null);
  const keyInput = useRef<HTMLInputElement | null>(null);
  const form = useRef<HTMLFormElement | null>(null);
  const operation = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const downloads = useRef(new LocalArtifactDownload());
  const identity = () => ({ enabled: validateIdentity, producer, source: producerSource });
  const clearInputs = () => {
    if (keyInput.current) {
      keyInput.current.value = '';
    }
    const input = form.current?.querySelector<HTMLInputElement>('[name="evidence-passphrase"]');
    if (input) {
      input.value = '';
    }
    setCandidate(false);
    setKeyRevision((value) => value + 1);
  };
  // biome-ignore lint/correctness/useExhaustiveDependencies: Actor/page/availability boundaries retire local output and unvalidated input, never a replacement login.
  useEffect(() => {
    generation.current++;
    operation.current?.abort();
    operation.current = null;
    downloads.current.clear();
    setOpened(null);
    setSelection(null);
    setReceived(null);
    setProtection(null);
    setVerified(null);
    setPhase(null);
    setNotice(null);
    setDetails(false);
    setUsed(null);
    setValidateIdentity(false);
    setProducer('');
    setProducerSource('reported');
    setSensitive(false);
    setLevel('private');
    setScope('complete');
    setAuditlog('');
    setID('');
    clearInputs();
    return () => {
      generation.current++;
      operation.current?.abort();
      operation.current = null;
      downloads.current.clear();
    };
  }, [access, disabled, view]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: Hide portals and clear unvalidated inputs on deactivation; retain the explicitly approved tab key cache.
  useEffect(() => {
    if (!active) {
      operation.current?.abort();
      clearInputs();
      setDetails(false);
    }
  }, [active]);
  const current = (token: number, signal: AbortSignal) =>
    token === generation.current && !signal.aborted && access.status() !== 'closed';
  async function run(
    next: Phase,
    action: (signal: AbortSignal, token: number, stage: (phase: Phase) => void) => Promise<void>,
  ) {
    if (disabled || operation.current !== null) {
      return;
    }
    const controller = new AbortController();
    const token = ++generation.current;
    operation.current = controller;
    let stage = next;
    setPhase(next);
    setNotice(null);
    setErrorCode('');
    setFailedStage(null);
    try {
      await action(controller.signal, token, (value) => {
        stage = value;
        if (current(token, controller.signal)) {
          setPhase(value);
        }
      });
    } catch (error) {
      if (token === generation.current) {
        reportUiError('artifact', error);
        setNotice(failure(error));
        setFailedStage(stage);
        setErrorCode(
          error instanceof EvidenceError || error instanceof RememberMeError
            ? error.code
            : 'unavailable',
        );
      }
    } finally {
      if (operation.current === controller) {
        operation.current = null;
        setPhase(null);
      }
    }
  }
  function resetResult() {
    downloads.current.clear();
    setVerified(null);
    setUsed(null);
    setNotice(null);
  }
  async function check(
    image: ReceivedArtifact,
    header: EvidenceMetadata,
    key: EvidenceKey | null,
    expectation: UsedExpectation,
    signal: AbortSignal,
    token: number,
    includeSensitive = sensitive,
  ) {
    const checked = {
      ...expectation,
      producer: expectation.enabled
        ? expectation.source === 'user'
          ? expectation.producer
          : header.producer
        : '',
    };
    if (current(token, signal)) {
      setUsed(checked);
    }
    const options = evidenceOptions(image.request, {
      producer: checked.producer,
      allowUntrusted: !expectation.enabled,
      recipient: level === 'outer' ? header.expectedRecipient : '',
      ...(level === 'private' && header.expectedRecipient !== '' ? { recipientFromKey: true } : {}),
      level,
      export: level === 'private',
      sensitive: level === 'private' && image.request.kind === 'audit' && includeSensitive,
      auditScope: image.request.kind === 'audit' ? scope : '',
    });
    const result = await verifyArtifact(image, options, key, signal);
    if (!current(token, signal)) {
      return;
    }
    if (key !== null) {
      secrets.remember(key, result);
      setCacheRevision((value) => value + 1);
    }
    resetResult();
    setVerified(result);
    setUsed(checked);
    clearInputs();
  }
  async function open(request: ArtifactRequest, summary?: RecordingSummary) {
    if (remoteDisabled || disabled || operation.current !== null) {
      return;
    }
    if (request.kind !== (view === 'recordings' ? 'recording' : 'audit')) {
      return;
    }
    resetResult();
    clearInputs();
    setReceived(null);
    setProtection(null);
    setOpened(request);
    setSelection(summary ?? null);
    setFilePage(0);
    setSensitive(false);
    const expected = identity();
    await run('downloading', async (signal, token, stage) => {
      artifactFields(request);
      const image = await access.downloadArtifact(request, signal);
      if (!current(token, signal)) {
        return;
      }
      setReceived(image);
      stage('inspecting');
      const header = await inspectProtection(image, signal, scope);
      if (!current(token, signal)) {
        return;
      }
      setProtection(header);
      if (expected.source === 'reported') {
        setProducer(header.producer);
      }
      const key =
        level === 'outer' || header.expectedRecipient === ''
          ? null
          : secrets.matching(header.expectedRecipient);
      if (level === 'outer' || header.expectedRecipient === '' || key !== null) {
        stage('verifying');
        await check(image, header, key, expected, signal, token, false);
      }
      heading.current?.focus();
    });
  }
  async function recheck() {
    if (received === null) {
      return;
    }
    const image = received;
    const previousHeader = protection;
    const file = keyInput.current?.files?.[0];
    const passphrase =
      form.current?.querySelector<HTMLInputElement>('[name="evidence-passphrase"]')?.value ?? '';
    const expected = identity();
    resetResult();
    await run(previousHeader ? 'verifying' : 'inspecting', async (signal, token, stage) => {
      const header = previousHeader ?? (await inspectProtection(image, signal, scope));
      if (!current(token, signal)) {
        return;
      }
      setProtection(header);
      if (expected.source === 'reported') {
        setProducer(header.producer);
      }
      let key =
        level === 'outer' || header.expectedRecipient === ''
          ? null
          : secrets.matching(header.expectedRecipient);
      if (level === 'private' && file !== undefined) {
        if (header.expectedRecipient === '' || file.size < 1 || file.size > 64 << 10) {
          throw new EvidenceError('key');
        }
        const bytes = await readLocalBytes(file, signal);
        try {
          key = { file: new Blob([bytes]), passphrase };
        } finally {
          new Uint8Array(bytes).fill(0);
        }
      }
      if (level === 'private' && header.expectedRecipient !== '' && key === null) {
        return;
      }
      stage('verifying');
      await check(image, header, key, expected, signal, token);
    });
  }
  function close() {
    generation.current++;
    operation.current?.abort();
    resetResult();
    clearInputs();
    setReceived(null);
    setProtection(null);
    setOpened(null);
    setSelection(null);
    setDetails(false);
  }
  function save(data: Blob, filename: string) {
    try {
      downloads.current.save(data, filename);
    } catch (error) {
      reportUiError('artifact-save', error);
      setNotice('artifactSaveFailed');
    }
  }
  const integrated = useAdminDetail(
    view,
    opened ? (opened.kind === 'recording' ? opened.id : opened.auditlog) : null,
    close,
  );
  const title = t(view === 'recordings' ? 'workspaceRecordings' : 'workspaceAuditlogs');
  const locked = disabled || phase !== null;
  const encrypted = (protection?.expectedRecipient ?? '') !== '';
  const cached = encrypted && secrets.has(protection?.expectedRecipient ?? '');
  const pinReady =
    !validateIdentity || (/^[0-9a-f]{64}$/u.test(producer) && !/^0+$/u.test(producer));
  const ready =
    received !== null &&
    (protection === null || level === 'outer' || !encrypted || candidate || cached) &&
    pinReady;
  const metadata = verified?.metadata;
  const success = verified !== null;
  const keyNeeded = level === 'private' && encrypted && !cached && !candidate;
  return (
    <section
      className="stack artifact-panel"
      aria-label={title}
      data-key-cache-revision={cacheRevision}
    >
      {!integrated && (
        <AdminBreadcrumbs
          items={[
            { label: t('workspaceBifroest') },
            { label: title, ...(opened ? { onClick: close } : {}) },
            ...(opened
              ? [{ label: opened.kind === 'recording' ? opened.id : opened.auditlog }]
              : []),
          ]}
        />
      )}
      <div className="section-heading">
        <h2 ref={heading} tabIndex={-1}>
          {title}
        </h2>
        {opened && (
          <div className="actions">
            <Button variant="default" disabled={locked} onClick={close}>
              {t('artifactBackToList')}
            </Button>
            <Button
              variant="subtle"
              onClick={() => setDetails(true)}
              aria-label={t('recordingVerificationDetails')}
            >
              {success ? (
                <CheckCircleIcon color="success" />
              ) : notice ? (
                <CancelIcon color="error" />
              ) : null}
              {t(
                success
                  ? metadata?.validation === 'outer'
                    ? 'artifactOuterVerified'
                    : used?.enabled && used.source === 'user'
                      ? 'artifactVerificationOK'
                      : 'artifactVerificationUnpinned'
                  : notice
                    ? 'artifactVerificationError'
                    : keyNeeded
                      ? 'artifactKeyNeeded'
                      : 'recordingVerificationDetails',
              )}
            </Button>
          </div>
        )}
      </div>
      <div hidden={opened !== null}>
        {view === 'recordings' ? (
          <ArtifactCatalog
            access={access}
            disabled={disabled || remoteDisabled}
            active={active && opened === null}
            onSelect={(request, summary) => {
              void open(request, summary);
            }}
          />
        ) : (
          <AuditCatalog
            access={access}
            disabled={disabled || remoteDisabled}
            active={active && opened === null}
            onSelect={(request) => {
              void open(request);
            }}
          />
        )}
        <details className="artifact-selection">
          <summary>{t('recordingManual')}</summary>
          <form
            method="dialog"
            className="actions"
            onSubmit={(event) => {
              event.preventDefault();
              void open(
                view === 'recordings'
                  ? { kind: 'recording', auditlog, id }
                  : { kind: 'audit', auditlog },
              );
            }}
          >
            <TextInput
              label={t('artifactAuditlog')}
              value={auditlog}
              onChange={(event) => setAuditlog(event.currentTarget.value)}
              required
              maxLength={128}
            />
            {view === 'recordings' && (
              <TextInput
                label={t('artifactRecordingID')}
                value={id}
                onChange={(event) => setID(event.currentTarget.value)}
                required
                maxLength={36}
              />
            )}
            <Button type="submit" disabled={disabled || remoteDisabled}>
              {t(view === 'recordings' ? 'recordingOpen' : 'recordingOpenAudit')}
            </Button>
          </form>
        </details>
      </div>
      {opened !== null && (
        <>
          {phase && (
            <div className="actions" role="status">
              <span>
                {t(
                  phase === 'downloading'
                    ? 'recordingOpening'
                    : phase === 'inspecting'
                      ? 'artifactInspecting'
                      : 'recordingVerifying',
                )}
              </span>
              <Button variant="default" onClick={() => operation.current?.abort()}>
                {t('artifactCancel')}
              </Button>
            </div>
          )}
          {notice && (
            <Alert color="red" role="status">
              {t(notice)}{' '}
              <Button variant="subtle" onClick={() => setDetails(true)}>
                {t('managementDetails')}
              </Button>
              {received === null && (
                <Button
                  disabled={locked || remoteDisabled}
                  onClick={() => {
                    void open(opened, selection ?? undefined);
                  }}
                >
                  {t('recordingRetryOpen')}
                </Button>
              )}
            </Alert>
          )}
          {received && (
            <>
              {(verified === null || candidate) && level === 'private' && encrypted && (
                <form
                  ref={form}
                  method="dialog"
                  className="stack artifact-key"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void recheck();
                  }}
                >
                  <p>{t(cached && !candidate ? 'artifactUsingCachedKey' : 'artifactKeyLocal')}</p>
                  <label htmlFor={inputID}>{t('artifactKeyFile')}</label>
                  <input
                    key={keyRevision}
                    ref={keyInput}
                    id={inputID}
                    name="evidence-private"
                    type="file"
                    disabled={locked}
                    onChange={(event) => {
                      const chosen = (event.currentTarget.files?.length ?? 0) > 0;
                      setCandidate(chosen);
                      const password = form.current?.querySelector<HTMLInputElement>(
                        '[name="evidence-passphrase"]',
                      );
                      if (password) {
                        password.value = '';
                      }
                    }}
                  />
                  {candidate && (
                    <PasswordInput
                      id={passwordID}
                      name="evidence-passphrase"
                      label={t('artifactPassphrase')}
                      autoComplete="off"
                      disabled={locked}
                    />
                  )}
                  <div className="actions">
                    <Button type="submit" disabled={locked || !ready}>
                      {t('artifactUnlock')}
                    </Button>
                    {cached && (
                      <Button
                        variant="subtle"
                        disabled={locked}
                        onClick={() => {
                          secrets.clear();
                          setCacheRevision((value) => value + 1);
                        }}
                      >
                        {t('artifactForgetKey')}
                      </Button>
                    )}
                  </div>
                </form>
              )}
              {verified?.output &&
                metadata?.kind === 'recording' &&
                metadata.outputFormat === 'cast' && (
                  <RecordingPlayer
                    source={verified.output}
                    expected={{
                      id: verified.request.kind === 'recording' ? verified.request.id : '',
                      producer: used?.enabled && used.source === 'user' ? used.producer : '',
                      allowUntrusted: !(used?.enabled && used.source === 'user'),
                    }}
                    disabled={disabled}
                    active={active}
                    autoPrepare
                  />
                )}
              {verified?.output &&
                metadata?.kind === 'audit' &&
                metadata.outputFormat === 'jsonl' && (
                  <AuditEvents source={verified.output} active={active} />
                )}
              <details className="artifact-verification">
                <summary>{t('artifactVerificationOptions')}</summary>
                <div className="stack">
                  <Select
                    label={t('artifactLevel')}
                    value={level}
                    disabled={locked}
                    data={[
                      { value: 'private', label: t('artifactPrivate') },
                      { value: 'outer', label: t('artifactOuter') },
                    ]}
                    onChange={(value) => {
                      setLevel(value === 'outer' ? 'outer' : 'private');
                      setSensitive(false);
                      resetResult();
                      clearInputs();
                    }}
                  />
                  {view === 'auditlogs' && (
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
                        setProtection(null);
                        resetResult();
                      }}
                    />
                  )}
                  <Checkbox
                    label={t('artifactCheckSigner')}
                    checked={validateIdentity}
                    disabled={locked}
                    onChange={(event) => {
                      setValidateIdentity(event.currentTarget.checked);
                      resetResult();
                    }}
                  />
                  <TextInput
                    label={t('artifactExpectedProducer')}
                    value={producer}
                    disabled={locked || !validateIdentity}
                    maxLength={64}
                    onChange={(event) => {
                      setProducer(event.currentTarget.value);
                      setProducerSource('user');
                      resetResult();
                    }}
                  />
                  {producerSource === 'reported' && (
                    <p className="caption subtle">{t('artifactSuggestedSigner')}</p>
                  )}
                  {view === 'auditlogs' && (
                    <Checkbox
                      label={t('artifactSensitive')}
                      checked={sensitive}
                      disabled={locked}
                      onChange={(event) => {
                        setSensitive(event.currentTarget.checked);
                        resetResult();
                      }}
                    />
                  )}
                  {encrypted && verified !== null && (
                    <Button
                      variant="subtle"
                      onClick={() => {
                        resetResult();
                        setCandidate(false);
                      }}
                    >
                      {t('artifactReplaceKey')}
                    </Button>
                  )}
                  <div className="actions">
                    <Button
                      disabled={locked || !ready}
                      onClick={() => {
                        void recheck();
                      }}
                    >
                      {t('artifactCheckAgain')}
                    </Button>
                    {secrets.fingerprint() !== null && (
                      <Button
                        variant="subtle"
                        disabled={locked}
                        onClick={() => {
                          secrets.clear();
                          setCacheRevision((value) => value + 1);
                        }}
                      >
                        {t('artifactForgetKey')}
                      </Button>
                    )}
                    {verified?.output && (
                      <Button
                        variant="default"
                        disabled={locked}
                        onClick={() => {
                          if (verified.output) {
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
                  </div>
                </div>
              </details>
            </>
          )}
        </>
      )}
      {received && opened?.kind === 'recording' && (
        <section className="recording-evidence">
          <ArtifactSourceDetails
            received={received}
            summary={selection}
            disabled={locked}
            page={filePage}
            onPage={setFilePage}
            onSave={save}
            showFiles={false}
          />
        </section>
      )}
      <Modal
        opened={active && details}
        onClose={() => setDetails(false)}
        title={t('recordingVerificationDetails')}
      >
        <div className="stack">
          {notice && <Alert color="red">{t(notice)}</Alert>}
          <dl className="metadata-grid">
            <dt>{t('artifactDiagnosticCode')}</dt>
            <dd>{errorCode || '—'}</dd>
            <dt>{t('artifactDiagnosticStage')}</dt>
            <dd>{failedStage ?? phase ?? 'complete'}</dd>
            <dt>{t('artifactValidation')}</dt>
            <dd>{metadata?.validation ?? protection?.validation ?? '—'}</dd>
            <dt>{t('artifactVerifiedProducer')}</dt>
            <dd>{metadata?.producer ?? protection?.producer ?? '—'}</dd>
            <dt>{t('artifactExpectedProducer')}</dt>
            <dd>{used?.enabled ? used.producer : t('artifactSignerNotPinned')}</dd>
            <dt>{t('artifactTrust')}</dt>
            <dd>
              {t(
                used?.enabled && used.source === 'user'
                  ? 'artifactUserSelectedSigner'
                  : 'artifactSuggestedSigner',
              )}
            </dd>
            <dt>{t('artifactDerivedRecipient')}</dt>
            <dd>
              {metadata?.expectedRecipient ||
                protection?.expectedRecipient ||
                t('artifactNotEncrypted')}
            </dd>
            <dt>{t('artifactDecryption')}</dt>
            <dd>{metadata?.decryption ?? 'not-checked'}</dd>
            {metadata?.kind === 'audit' && (
              <>
                <dt>{t('artifactRecordCount')}</dt>
                <dd>{metadata.records}</dd>
                <dt>{t('artifactPrivateCount')}</dt>
                <dd>{metadata.privateRecords}</dd>
                <dt>{t('artifactAuditScope')}</dt>
                <dd>{metadata.auditScope}</dd>
              </>
            )}
          </dl>
          {received && (
            <>
              <ArtifactSourceDetails
                received={received}
                summary={selection}
                disabled={locked}
                page={filePage}
                onPage={setFilePage}
                onSave={save}
                showFiles={false}
              />
              <details>
                <summary>{t('artifactOriginalsAdvanced')}</summary>
                <ArtifactSourceDetails
                  received={received}
                  disabled={locked}
                  page={filePage}
                  onPage={setFilePage}
                  onSave={save}
                  showMetadata={false}
                />
              </details>
            </>
          )}
        </div>
      </Modal>
    </section>
  );
}
