import { Dialog, DialogActions, DialogContent, DialogTitle } from '@mui/material';
import { useEffect, useId, useState } from 'react';
import { Button } from '../ui/material';
import { t } from '../ui/messages';

export function VerifyAllButton({
  source,
  kind,
  disabled,
  onConfirm,
}: {
  source: string;
  kind: 'recordings' | 'audit';
  disabled: boolean;
  onConfirm(source: string): void;
}) {
  const [intent, setIntent] = useState('');
  const title = useId();
  useEffect(() => {
    if (disabled || (intent && intent !== source)) {
      setIntent('');
    }
  }, [disabled, intent, source]);
  return (
    <>
      <Button
        variant="default"
        disabled={disabled || source === ''}
        onClick={() => setIntent(source)}
      >
        {t('verifyAll')}
      </Button>
      <Dialog
        open={intent !== ''}
        onClose={() => setIntent('')}
        aria-labelledby={title}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle id={title}>{t('verifyAllTitle')}</DialogTitle>
        <DialogContent>
          <p>
            {t('verifyAllSource')}: <strong>{intent}</strong>
          </p>
          <p>{t(kind === 'recordings' ? 'verifyAllRecordingsScope' : 'verifyAllAuditScope')}</p>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setIntent('')}>{t('cancel')}</Button>
          <Button
            disabled={disabled || intent !== source}
            onClick={() => {
              const selected = intent;
              setIntent('');
              onConfirm(selected);
            }}
          >
            {t('verifyAll')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
