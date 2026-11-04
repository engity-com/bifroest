import { Button, Title } from '../ui/material';
import { t } from '../ui/messages';
import type { ReceivedArtifact } from './protocol';

export function ArtifactSourceDetails({
  received,
  disabled,
  page,
  onPage,
  onSave,
}: {
  received: ReceivedArtifact;
  disabled: boolean;
  page: number;
  onPage(page: number): void;
  onSave(data: Blob, filename: string): void;
}) {
  return (
    <section className="stack" aria-label={t('artifactHints')}>
      <Title order={4}>{t('artifactHints')}</Title>
      <p className="caption subtle">{t('artifactTransportWarning')}</p>
      <dl className="metadata-grid">
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
    </section>
  );
}
