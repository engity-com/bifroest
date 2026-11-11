import CancelIcon from '@mui/icons-material/Cancel';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import { Box, IconButton, Skeleton, Tooltip } from '@mui/material';
import { createContext, type ReactNode, useContext } from 'react';
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
  readonly result?: 'success' | 'failure' | undefined;
  readonly onStatusClick?: (() => void) | undefined;
}
export interface GridDetails {
  readonly checked: boolean;
  readonly onChange: () => void;
  readonly disabled?: boolean;
  readonly label?: Message;
  readonly showLabel?: Message;
}
export const GridWorkContext = createContext<GridWork | undefined>(undefined);
export type GridActions = (disabled: boolean) => ReactNode;
export const GridActionsContext = createContext<GridActions | undefined>(undefined);
export const GridEmptyStateContext = createContext<ReactNode>(null);
export function GridEmptyOverlay() {
  const content = useContext(GridEmptyStateContext);
  return (
    <Box
      className="MuiDataGrid-overlay"
      sx={{
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        p: 3,
        textAlign: 'center',
        whiteSpace: 'normal',
        '& .stack': { maxWidth: '36rem', alignItems: 'center' },
      }}
    >
      {content}
    </Box>
  );
}
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
        <IconButton
          size="small"
          disabled={work.disabled}
          aria-label={t(label)}
          data-grid-work-mode={work.mode}
          data-grid-cancel={work.mode === 'cancel' || undefined}
          onClick={work.onClick}
        >
          {work.mode === 'cancel' ? (
            <CancelIcon fontSize="small" />
          ) : work.mode === 'server' ? (
            <DirectServerIcon fontSize="small" />
          ) : (
            <LicenseIcon fontSize="small" />
          )}
        </IconButton>
      </span>
    </Tooltip>
  );
}
export function VerificationResultButton({
  result,
  onClick,
  disabled = false,
}: {
  result: 'success' | 'failure';
  onClick(): void;
  disabled?: boolean;
}) {
  return (
    <Tooltip title={t('recordingVerificationDetails')}>
      <span>
        <IconButton
          size="small"
          aria-label={t('recordingVerificationDetails')}
          disabled={disabled}
          data-verification-result={result}
          onClick={onClick}
        >
          {result === 'success' ? (
            <CheckCircleIcon color="success" />
          ) : (
            <CancelIcon color="error" />
          )}
        </IconButton>
      </span>
    </Tooltip>
  );
}
// Loading replaces retained data and locks the grid, not the surrounding page.
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
        bgcolor: 'background.paper',
        position: 'relative',
      }}
    >
      <Box aria-hidden="true" sx={{ position: 'absolute', inset: 0, p: 2, overflow: 'hidden' }}>
        {Array.from({ length: 20 }, (_, index) => `placeholder-${index}`).map((key) => (
          <Skeleton key={key} variant="rounded" height={32} sx={{ mb: 1 }} />
        ))}
      </Box>
      <Box
        sx={{
          width: 'min(90%, 28rem)',
          p: 2,
          bgcolor: 'background.paper',
          border: 1,
          borderColor: 'divider',
          borderRadius: 1,
          boxShadow: 1,
          zIndex: 1,
        }}
      >
        {progress.visible ? <ReadProgress value={progress.value} /> : <ReadProgress value={null} />}
      </Box>
    </Box>
  );
}
