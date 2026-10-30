import { useEffect, useRef, useState } from 'react';
import type { AuditlogSummary, Page, RecordingSummary, WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { Alert, Button, Table, Title } from '../ui/material';
import { t } from '../ui/messages';
import type { ArtifactRequest } from './protocol';

export function ArtifactCatalog({
  access,
  disabled,
  onSelect,
}: {
  access: WebAccess;
  disabled: boolean;
  onSelect: (request: ArtifactRequest) => void;
}) {
  const [auditlogs, setAuditlogs] = useState<Page<AuditlogSummary> | null>(null);
  const [recordings, setRecordings] = useState<{
    auditlog: string;
    page: Page<RecordingSummary>;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const [cancelled, setCancelled] = useState(false);
  const operation = useRef<AbortController | null>(null);
  const generation = useRef(0);

  // biome-ignore lint/correctness/useExhaustiveDependencies: An actor change retires every actor-owned page and in-flight response.
  useEffect(() => {
    generation.current++;
    operation.current?.abort();
    operation.current = null;
    setAuditlogs(null);
    setRecordings(null);
    setBusy(false);
    setFailed(false);
    setCancelled(false);
    return () => {
      generation.current++;
      operation.current?.abort();
      operation.current = null;
    };
  }, [access]);
  useEffect(() => {
    if (disabled && operation.current !== null) {
      generation.current++;
      operation.current.abort();
      // Retain the slot until cleanup joins. Completed same-actor pages may
      // remain visible but are disabled; authentication changes clear them.
    }
  }, [disabled]);

  async function run(action: (signal: AbortSignal, current: number) => Promise<void>) {
    if (disabled || operation.current !== null) {
      return;
    }
    const controller = new AbortController();
    const current = ++generation.current;
    operation.current = controller;
    setBusy(true);
    setFailed(false);
    setCancelled(false);
    try {
      await action(controller.signal, current);
    } catch (error) {
      if (
        current === generation.current &&
        !(error instanceof RememberMeError && error.code === 'cancelled')
      ) {
        setFailed(true);
      }
    } finally {
      if (operation.current === controller) {
        operation.current = null;
        setBusy(false);
      }
    }
  }
  function cancel() {
    generation.current++;
    operation.current?.abort();
    setCancelled(true);
  }
  async function loadAuditlogs(after = '') {
    await run(async (signal, current) => {
      setAuditlogs(null);
      setRecordings(null);
      const page = await access.managementAuditlogs({ after }, signal);
      if (current === generation.current && !signal.aborted) {
        setAuditlogs(page);
      }
    });
  }
  async function loadRecordings(auditlog: string, after = '') {
    await run(async (signal, current) => {
      setRecordings(null);
      const page = await access.managementRecordings(auditlog, { after }, signal);
      if (current === generation.current && !signal.aborted) {
        setRecordings({ auditlog, page });
      }
    });
  }
  function select(request: ArtifactRequest) {
    if (!disabled && operation.current === null) {
      onSelect(request);
    }
  }
  const locked = disabled || busy;
  const when = (value: string) =>
    new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'short' }).format(
      new Date(value),
    );
  return (
    <section className="stack" aria-label={t('artifactCatalog')}>
      <Title order={3}>{t('artifactCatalog')}</Title>
      <details className="context-help">
        <summary>{t('artifactCatalogHelp')}</summary>
        <p>{t('artifactCatalogWarning')}</p>
      </details>
      {((auditlogs !== null && auditlogs.skipped > 0) ||
        (recordings !== null && recordings.page.skipped > 0)) && (
        <Alert color="yellow">{t('managementPartial')}</Alert>
      )}
      {failed && (
        <Alert role="status" color="red">
          {t('artifactCatalogFailed')}
        </Alert>
      )}
      {cancelled && (
        <Alert role="status" color="yellow">
          {t('artifactCatalogCancelled')}
        </Alert>
      )}
      <div className="actions">
        <Button
          disabled={locked}
          onClick={() => {
            void loadAuditlogs();
          }}
        >
          {t('artifactLoadAuditlogs')}
        </Button>
        {busy && (
          <Button variant="default" onClick={cancel}>
            {t('artifactCatalogCancel')}
          </Button>
        )}
      </div>
      {auditlogs !== null && (
        <>
          <div className="table-scroll">
            <Table captionSide="top">
              <caption>{t('artifactAuditlogCaption')}</caption>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('artifactAuditlog')}</Table.Th>
                  <Table.Th>{t('artifactCatalogConfiguration')}</Table.Th>
                  <Table.Th>{t('artifactCatalogSelection')}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {auditlogs.items.map((row) => (
                  <Table.Tr key={row.name}>
                    <Table.Td>{row.name}</Table.Td>
                    <Table.Td>
                      {t(row.enabled ? 'artifactCatalogEnabled' : 'artifactCatalogDisabled')} /{' '}
                      {t(
                        row.recordingEnabled
                          ? 'artifactCatalogRecordingOn'
                          : 'artifactCatalogRecordingOff',
                      )}{' '}
                      / {t(row.encrypted ? 'artifactCatalogEncrypted' : 'artifactCatalogClear')}
                    </Table.Td>
                    <Table.Td>
                      <div className="stack">
                        <Button
                          disabled={locked || !row.enabled}
                          aria-label={`${t('artifactSelectAudit')} ${row.name}`}
                          onClick={() => select({ kind: 'audit', auditlog: row.name })}
                        >
                          {t('artifactSelectAudit')}
                        </Button>
                        <Button
                          disabled={locked || !row.enabled || !row.recordingEnabled}
                          aria-label={`${t('artifactLoadRecordings')} ${row.name}`}
                          onClick={() => {
                            void loadRecordings(row.name);
                          }}
                        >
                          {t('artifactLoadRecordings')}
                        </Button>
                      </div>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </div>
          {auditlogs.items.length === 0 && <p>{t('artifactCatalogEmpty')}</p>}
          {auditlogs.next !== '' && (
            <Button
              disabled={locked}
              onClick={() => {
                void loadAuditlogs(auditlogs.next);
              }}
            >
              {t('artifactNextAuditlogs')}
            </Button>
          )}
        </>
      )}
      {recordings !== null && (
        <section className="stack" aria-label={t('artifactRecordingCatalog')}>
          <Title order={4}>
            {t('artifactRecordingCatalog')}: {recordings.auditlog}
          </Title>
          <div className="table-scroll">
            <Table captionSide="top">
              <caption>{t('artifactRecordingCaption')}</caption>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('artifactRecordingID')}</Table.Th>
                  <Table.Th>{t('artifactCatalogRecordingMetadata')}</Table.Th>
                  <Table.Th>{t('artifactCatalogSelection')}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {recordings.page.items.map((row) => (
                  <Table.Tr key={row.id}>
                    <Table.Td>{row.id}</Table.Td>
                    <Table.Td>
                      {row.format} /{' '}
                      {t(
                        row.status === 'completed'
                          ? 'artifactCatalogCompleted'
                          : row.status === 'failed'
                            ? 'artifactCatalogFailedStatus'
                            : 'artifactCatalogIncomplete',
                      )}
                      <br />
                      {when(row.startedAt)} /{' '}
                      {new Intl.NumberFormat('en-US').format(row.containerBytes)}{' '}
                      {t('artifactBytes')}
                      <br />
                      <span>
                        {t(
                          row.verificationScope === 'outer'
                            ? 'artifactCatalogServerOuter'
                            : 'artifactCatalogServerFull',
                        )}
                      </span>
                    </Table.Td>
                    <Table.Td>
                      <Button
                        disabled={locked}
                        aria-label={`${t('artifactSelectRecording')} ${row.id}`}
                        onClick={() =>
                          select({ kind: 'recording', auditlog: row.auditlog, id: row.id })
                        }
                      >
                        {t('artifactSelectRecording')}
                      </Button>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </div>
          {recordings.page.items.length === 0 && <p>{t('artifactCatalogEmpty')}</p>}
          {recordings.page.next !== '' && (
            <Button
              disabled={locked}
              onClick={() => {
                void loadRecordings(recordings.auditlog, recordings.page.next);
              }}
            >
              {t('artifactNextRecordings')}
            </Button>
          )}
        </section>
      )}
    </section>
  );
}
