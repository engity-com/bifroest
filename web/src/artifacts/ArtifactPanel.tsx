import {
  Alert,
  Button,
  Checkbox,
  Paper,
  PasswordInput,
  Select,
  TextInput,
  Title,
} from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import type { WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import type { Message } from '../ui/messages';
import { t } from '../ui/messages';
import { ArtifactCatalog } from './ArtifactCatalog';
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
      : 'artifactDownloadFailed';
}

export function ArtifactPanel({ access, disabled }: { access: WebAccess; disabled: boolean }) {
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
  const [level, setLevel] = useState<'outer' | 'private'>('outer');
  const [scope, setScope] = useState<'complete' | 'captured-prefix'>('complete');
  const [exporting, setExporting] = useState(false);
  const [sensitive, setSensitive] = useState(false);
  const [phase, setPhase] = useState<'downloading' | 'verifying' | null>(null);
  const [notice, setNotice] = useState<Message | null>(null);
  const [keyRevision, setKeyRevision] = useState(0);
  const form = useRef<HTMLFormElement | null>(null);
  const operation = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const downloads = useRef(new LocalArtifactDownload());

  function clearKey() {
    for (const selector of ['#evidence-private', '#evidence-passphrase']) {
      const input = form.current?.querySelector<HTMLInputElement>(selector);
      if (input) {
        input.value = '';
      }
    }
    setKeyRevision((value) => value + 1); // Reset Mantine's uncontrolled internal state too.
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
    setLevel('outer');
    setScope('complete');
    setExporting(false);
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
    clearKey();
    return () => {
      generation.current++;
      operation.current?.abort();
      operation.current = null;
      downloads.current.clear();
      for (const selector of ['#evidence-private', '#evidence-passphrase']) {
        const input = form.current?.querySelector<HTMLInputElement>(selector);
        if (input) {
          input.value = '';
        }
      }
    };
  }, [access, disabled]);

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

  async function download() {
    clearKey();
    await run('downloading', async (signal, current) => {
      setReceived(null);
      setFilePage(0);
      const selected: ArtifactRequest =
        kind === 'recording' ? { kind, auditlog, id } : { kind, auditlog };
      try {
        artifactFields(selected);
      } catch {
        throw new EvidenceError('input');
      }
      const result = await access.downloadArtifact(selected, signal);
      if (current === generation.current && !signal.aborted) {
        setReceived(result);
      }
    });
  }

  async function verify() {
    const selected = received;
    if (selected === null || disabled || operation.current !== null) {
      return;
    }
    let key: EvidenceKey | null = null;
    const file = form.current?.querySelector<HTMLInputElement>('#evidence-private')?.files?.[0];
    const password =
      form.current?.querySelector<HTMLInputElement>('#evidence-passphrase')?.value ?? '';
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
    } catch {
      setNotice('artifactSaveFailed');
    }
  }

  const locked = disabled || phase !== null;
  const metadata = verified?.metadata;
  return (
    <Paper
      withBorder
      p="lg"
      className="stack artifact-panel"
      component="section"
      aria-label={t('artifactTitle')}
    >
      <Title order={2}>{t('artifactTitle')}</Title>
      <Alert color="blue">{t('artifactIntroduction')}</Alert>
      <ArtifactCatalog
        access={access}
        disabled={locked}
        onSelect={(request) => {
          if (disabled || operation.current !== null) {
            return;
          }
          setKind(request.kind);
          setAuditlog(request.auditlog);
          setID(request.kind === 'recording' ? request.id : '');
          selectionChanged();
        }}
      />
      {notice !== null && (
        <Alert role="status" color={notice === 'artifactCancelled' ? 'yellow' : 'red'}>
          {t(notice)}
        </Alert>
      )}
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
          disabled={locked}
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
          disabled={locked}
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
            disabled={locked}
            onChange={(event) => {
              setID(event.currentTarget.value);
              selectionChanged();
            }}
          />
        )}
        <Button type="submit" disabled={locked}>
          {t('artifactDownload')}
        </Button>
      </form>
      {phase !== null && (
        <div role="status" className="actions">
          <p>{t(phase === 'downloading' ? 'artifactDownloading' : 'artifactVerifying')}</p>
          <Button variant="default" onClick={cancel}>
            {t('artifactCancel')}
          </Button>
        </div>
      )}
      {received !== null && (
        <>
          <Alert color="yellow">{t('artifactTransportComplete')}</Alert>
          <section aria-label={t('artifactHints')}>
            <Title order={3}>{t('artifactHints')}</Title>
            <p>{t('artifactTransportWarning')}</p>
            <dl>
              <dt>{t('artifactSelected')}</dt>
              <dd>
                {received.request.auditlog}
                {received.request.kind === 'recording' ? ` / ${received.request.id}` : ''}
              </dd>
              <dt>{t('artifactProducerHint')}</dt>
              <dd>
                {'ProducerID' in received.metadata
                  ? received.metadata.ProducerID
                  : received.metadata.Producer}
              </dd>
              {'Recipient' in received.metadata && (
                <>
                  <dt>{t('artifactRecipientHint')}</dt>
                  <dd>{received.metadata.Recipient || t('artifactHintNone')}</dd>
                </>
              )}
            </dl>
            <ul>
              {received.files.slice(filePage * 20, (filePage + 1) * 20).map((file) => (
                <li key={file.name}>
                  {file.name} ({new Intl.NumberFormat('en-US').format(file.data.size)}{' '}
                  {t('artifactBytes')}){' '}
                  <Button
                    variant="subtle"
                    disabled={locked}
                    onClick={() =>
                      save(
                        file.data,
                        file.name === 'recording' && received.request.kind === 'recording'
                          ? `recording-${received.request.id}.bin`
                          : file.name,
                      )
                    }
                  >
                    {t('artifactSaveOriginal')} {file.name}
                  </Button>
                </li>
              ))}
            </ul>
            <div className="actions">
              {filePage > 0 && (
                <Button
                  variant="default"
                  disabled={locked}
                  onClick={() => setFilePage((value) => value - 1)}
                >
                  {t('artifactPreviousFiles')}
                </Button>
              )}
              {(filePage + 1) * 20 < received.files.length && (
                <Button
                  variant="default"
                  disabled={locked}
                  onClick={() => setFilePage((value) => value + 1)}
                >
                  {t('artifactNextFiles')}
                </Button>
              )}
            </div>
          </section>
          <form
            ref={form}
            method="dialog"
            className="stack"
            onSubmit={(event) => {
              event.preventDefault();
              void verify();
            }}
          >
            <Title order={3}>{t('artifactExpectations')}</Title>
            <Alert color="blue">{t('artifactIndependentPins')}</Alert>
            <Checkbox
              label={t('artifactAllowUntrusted')}
              checked={untrusted}
              disabled={locked}
              onChange={(event) => {
                setUntrusted(event.currentTarget.checked);
                invalidateResult();
              }}
            />
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
                {encryption === 'encrypted' && (
                  <>
                    <Alert color="blue">{t('artifactKeyLocal')}</Alert>
                    <label className="stack" htmlFor="evidence-private">
                      {t('artifactKeyFile')}
                      <input
                        key={`private:${keyRevision}`}
                        id="evidence-private"
                        type="file"
                        required
                        disabled={locked}
                      />
                    </label>
                    <PasswordInput
                      key={`passphrase:${keyRevision}`}
                      id="evidence-passphrase"
                      label={t('artifactPassphrase')}
                      disabled={locked}
                      autoComplete="off"
                      visibilityToggleButtonProps={{ 'aria-label': t('togglePassword') }}
                    />
                  </>
                )}
              </>
            )}
            <Button type="submit" disabled={locked}>
              {t('artifactVerify')}
            </Button>
          </form>
        </>
      )}
      {verified !== null && metadata !== undefined && (
        <section className="stack" aria-label={t('artifactResult')} aria-live="polite">
          <Title order={3}>{t('artifactResult')}</Title>
          {metadata.trust === 'untrusted' && (
            <Alert color="yellow">{t('artifactUntrustedResult')}</Alert>
          )}
          <dl>
            <dt>{t('artifactTrust')}</dt>
            <dd>
              {t(metadata.trust === 'pinned' ? 'artifactPinnedResult' : 'artifactUntrustedResult')}
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
          {verified.output !== null && (
            <Button
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
              />
            )}
        </section>
      )}
      {received !== null && (
        <Button
          variant="default"
          disabled={locked}
          onClick={() => {
            setReceived(null);
            invalidateResult();
          }}
        >
          {t('artifactClearTab')}
        </Button>
      )}
    </Paper>
  );
}
