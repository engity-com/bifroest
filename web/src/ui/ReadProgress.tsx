import { LinearProgress } from '@mui/material';
import type { ReadProgress as Progress } from '../management/progress';
import { Button } from './material';
import { type Message, t } from './messages';

const labels: Record<string, Message> = {
  waiting: 'scanWaiting',
  inventory: 'scanInventory',
  verifying: 'scanVerifying',
  reverifying: 'scanReverifying',
  finalizing: 'scanFinalizing',
  receiving: 'scanReceiving',
  validating: 'scanValidating',
  reading: 'scanReading',
  integrity: 'scanIntegrity',
  decrypting: 'scanDecrypting',
  exporting: 'scanExporting',
  indexing: 'scanIndexing',
  filtering: 'scanFiltering',
};
export function ReadProgress({
  value,
  onCancel,
  cancelLabel = 'artifactCatalogCancel',
}: {
  value: Progress | null;
  onCancel(): void;
  cancelLabel?: Message;
}) {
  const known = value !== null && value.total > 0;
  const number = new Intl.NumberFormat();
  return (
    <div className="stack" role="status" aria-live="polite">
      <div className="actions">
        <span>
          {t(labels[value?.phase ?? 'waiting'] ?? 'scanWaiting')}
          {value && (
            <>
              {' '}
              · {number.format(value.completed)}
              {value.total >= 0 && <> / {number.format(value.total)}</>}
              {value.phase === 'receiving' || value.phase === 'reading' ? ' B' : ''}
            </>
          )}
        </span>
        <Button variant="default" onClick={onCancel}>
          {t(cancelLabel)}
        </Button>
      </div>
      <LinearProgress
        variant={known ? 'determinate' : 'indeterminate'}
        {...(known ? { value: (100 * value.completed) / value.total } : {})}
      />
    </div>
  );
}
