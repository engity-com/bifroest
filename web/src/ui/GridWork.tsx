import CancelIcon from '@mui/icons-material/Cancel';
import { Box, Button, Tooltip } from '@mui/material';
import { createContext, useContext } from 'react';
import type { ReadProgress as Progress } from '../management/progress';
import { DirectServerIcon } from './DirectServerIcon';
import { LicenseIcon } from './LicenseIcon';
import { type Message, t } from './messages';
import { ReadProgress } from './ReadProgress';

export interface GridWork {
  readonly mode: 'verify' | 'cancel' | 'server';
  readonly onClick: () => void;
  readonly disabled?: boolean;
  readonly progress?: Progress | null;
  readonly status?: string | undefined;
  readonly onStatusClick?: (() => void) | undefined;
}
export interface GridDetails {
  readonly checked: boolean;
  readonly onChange: () => void;
  readonly disabled?: boolean;
  readonly label?: Message;
}
export const GridWorkContext = createContext<GridWork | undefined>(undefined);
export const GridProgressContext = createContext<{ visible: boolean; value: Progress | null }>({
  visible: false,
  value: null,
});
export function GridWorkButton({ work }: { work: GridWork }) {
  const label =
    work.mode === 'cancel'
      ? 'verifyAllCancel'
      : work.mode === 'server'
        ? 'directServerData'
        : 'verifyOpen';
  return (
    <Tooltip title={t(label)}>
      <span>
        <Button
          size="small"
          disabled={work.disabled}
          aria-label={t(label)}
          data-grid-work-mode={work.mode}
          onClick={work.onClick}
          startIcon={
            work.mode === 'cancel' ? (
              <CancelIcon fontSize="small" />
            ) : work.mode === 'server' ? (
              <DirectServerIcon fontSize="small" />
            ) : (
              <LicenseIcon fontSize="small" />
            )
          }
        >
          {work.mode === 'server' ? t(label) : null}
        </Button>
      </span>
    </Tooltip>
  );
}
// The overlay belongs to this grid. It never becomes a page scrim or disables
// retained rows/filters/paging while a separate full-verification job runs.
export function GridLoadingOverlay() {
  const progress = useContext(GridProgressContext);
  return (
    <Box
      data-testid="GridLoadingOverlay"
      sx={{
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        pointerEvents: 'none',
      }}
    >
      <Box
        sx={{
          width: 'min(90%, 28rem)',
          p: 2,
          bgcolor: 'background.paper',
          border: 1,
          borderColor: 'divider',
          borderRadius: 1,
          boxShadow: 1,
        }}
      >
        {progress.visible ? <ReadProgress value={progress.value} /> : <ReadProgress value={null} />}
      </Box>
    </Box>
  );
}
