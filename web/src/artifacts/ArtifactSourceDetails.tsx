import type { RecordingSummary } from '../management/protocol';
import { Button, Title } from '../ui/material';
import { t } from '../ui/messages';
import type { ReceivedArtifact } from './protocol';

export function ArtifactSourceDetails({
  received,
  disabled,
  page,
  onPage,
  onSave,
  summary,
  showFiles = true,
  showMetadata = true,
}: {
  received: ReceivedArtifact;
  disabled: boolean;
  page: number;
  onPage(page: number): void;
  onSave(data: Blob, filename: string): void;
  summary?: RecordingSummary | null;
  showFiles?: boolean;
  showMetadata?: boolean;
}) {
  return (
    <section className="stack" aria-label={t('artifactHints')}>
      {showMetadata && (
        <>
          <Title order={4}>
            {t(
              showFiles
                ? 'artifactHints'
                : received.request.kind === 'recording'
                  ? 'recordingDetails'
                  : 'auditLogDetails',
            )}
          </Title>
          <p className="caption subtle">
            {t(showFiles ? 'artifactTransportWarning' : 'recordingServerMetadata')}
          </p>
          <dl className="metadata-grid">
            <dt>{t('artifactSelected')}</dt>
            <dd>
              {received.request.auditlog}
              {received.request.kind === 'recording' ? ` / ${received.request.id}` : ''}
            </dd>
            {summary && (
              <>
                <dt>{t('recordingIdentity')}</dt>
                <dd>{summary.user || t('recordingMetadataUnknown')}</dd>
                <dt>{t('recordingFilterFlow')}</dt>
                <dd>{summary.flow || '—'}</dd>
                <dt>{t('recordingFilterTarget')}</dt>
                <dd>{summary.target || '—'}</dd>
                <dt>{t('recordingStarted')}</dt>
                <dd>
                  {new Intl.DateTimeFormat(undefined, {
                    dateStyle: 'medium',
                    timeStyle: 'short',
                  }).format(new Date(summary.startedAt))}
                </dd>
                <dt>{t('recordingFilterStatus')}</dt>
                <dd>{summary.status}</dd>
                <dt>{t('recordingSize')}</dt>
                <dd>
                  {new Intl.NumberFormat().format(summary.containerBytes)} {t('artifactBytes')}
                </dd>
              </>
            )}
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
        </>
      )}
      {showFiles && (
        <>
          <ul>
            {received.files.slice(page * 20, (page + 1) * 20).map((file) => (
              <li key={file.name}>
                {file.name} ({new Intl.NumberFormat('en-US').format(file.data.size)}{' '}
                {t('artifactBytes')}){' '}
                <Button
                  variant="subtle"
                  disabled={disabled}
                  onClick={() =>
                    onSave(
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
          <div className="artifact-actions">
            {page > 0 && (
              <Button variant="default" disabled={disabled} onClick={() => onPage(page - 1)}>
                {t('artifactPreviousFiles')}
              </Button>
            )}
            {(page + 1) * 20 < received.files.length && (
              <Button variant="default" disabled={disabled} onClick={() => onPage(page + 1)}>
                {t('artifactNextFiles')}
              </Button>
            )}
          </div>
        </>
      )}
    </section>
  );
}
