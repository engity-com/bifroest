import CancelIcon from '@mui/icons-material/Cancel';
import FilterListIcon from '@mui/icons-material/FilterList';
import PushPinIcon from '@mui/icons-material/PushPin';
import RefreshIcon from '@mui/icons-material/Refresh';
import VisibilityIcon from '@mui/icons-material/Visibility';
import VisibilityOffIcon from '@mui/icons-material/VisibilityOff';
import { Box, ClickAwayListener, Paper, Popper, Tooltip } from '@mui/material';
import { FilterPanelTrigger, Toolbar, ToolbarButton } from '@mui/x-data-grid';
import { createContext, type ReactNode, useContext, useEffect, useState } from 'react';
import { setDetailedView, useDetailedView } from './detail-preference';
import {
  type GridDetails,
  type GridWork,
  GridWorkButton,
  VerificationResultButton,
} from './GridWork';
import { t } from './messages';

export interface AdminGridControls {
  active: boolean;
  disabled: boolean;
  busy: boolean;
  filterable: boolean;
  onRefresh?: (() => void) | undefined;
  refreshLabel?: string | undefined;
  detailsAvailable: boolean;
  openByID?: ReactNode;
  work?: GridWork | undefined;
  detailToggle?: GridDetails | undefined;
  onCancelRead?: (() => void) | undefined;
}
export const AdminGridControlsContext = createContext<AdminGridControls | null>(null);
export function AdminGridToolbar() {
  const controls = useContext(AdminGridControlsContext);
  const detailed = useDetailedView();
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  useEffect(() => {
    if (!controls?.active || controls.disabled || controls.busy) {
      setAnchor(null);
    }
  }, [controls?.active, controls?.disabled, controls?.busy]);
  if (!controls) {
    return null;
  }
  const locked = controls.busy || controls.disabled || !controls.active;
  const showDetails = controls.detailToggle?.checked ?? detailed;
  const cancellingRead =
    controls.busy && controls.work?.mode !== 'cancel' && !!controls.onCancelRead;
  const refreshLabel = cancellingRead
    ? t('artifactCatalogCancel')
    : (controls.refreshLabel ?? t('adminGridRefresh'));
  const eyeLabel = t(
    controls.detailsAvailable && showDetails ? 'adminGridHideDetails' : 'adminGridShowDetails',
  );
  return (
    <Toolbar aria-label={t('adminGridToolbar')}>
      <Box sx={{ flex: 1 }} />
      {controls.work?.result && controls.work.onStatusClick && (
        <VerificationResultButton
          result={controls.work.result}
          onClick={controls.work.onStatusClick}
          disabled={locked}
        />
      )}
      {controls.work && (
        <GridWorkButton
          work={{
            ...controls.work,
            disabled:
              !!controls.work.disabled ||
              controls.disabled ||
              !controls.active ||
              (controls.busy && controls.work.mode !== 'cancel'),
          }}
        />
      )}
      <Tooltip title={refreshLabel}>
        <span>
          <ToolbarButton
            aria-label={refreshLabel}
            data-grid-cancel={cancellingRead || undefined}
            disabled={
              controls.disabled ||
              !controls.active ||
              (cancellingRead ? false : locked || !controls.onRefresh)
            }
            onClick={cancellingRead ? controls.onCancelRead : controls.onRefresh}
          >
            {cancellingRead ? <CancelIcon fontSize="small" /> : <RefreshIcon fontSize="small" />}
          </ToolbarButton>
        </span>
      </Tooltip>
      <Tooltip title={eyeLabel}>
        <span>
          <ToolbarButton
            aria-label={eyeLabel}
            aria-pressed={controls.detailsAvailable && showDetails}
            disabled={locked || !controls.detailsAvailable || !!controls.detailToggle?.disabled}
            onClick={() =>
              controls.detailToggle ? controls.detailToggle.onChange() : setDetailedView(!detailed)
            }
          >
            {controls.detailsAvailable && showDetails ? (
              <VisibilityOffIcon fontSize="small" />
            ) : (
              <VisibilityIcon fontSize="small" />
            )}
          </ToolbarButton>
        </span>
      </Tooltip>
      {controls.openByID && (
        <Tooltip title={anchor === null ? t('recordingManual') : ''}>
          <ToolbarButton
            aria-label={t('recordingManual')}
            aria-expanded={anchor !== null}
            aria-haspopup="dialog"
            disabled={locked}
            onClick={(event) => setAnchor(anchor ? null : event.currentTarget)}
          >
            <PushPinIcon fontSize="small" />
          </ToolbarButton>
        </Tooltip>
      )}
      {controls.filterable && (
        <Tooltip title="Filters">
          <FilterPanelTrigger render={<ToolbarButton aria-label="Filters" disabled={locked} />}>
            <FilterListIcon fontSize="small" />
          </FilterPanelTrigger>
        </Tooltip>
      )}
      <Popper
        open={controls.active && anchor !== null}
        anchorEl={anchor}
        placement="bottom-end"
        sx={{ zIndex: 1300 }}
      >
        {/* Leading events keep a Select's newly opened portal from turning the
            remainder of its opening pointer gesture into an outside click. */}
        <ClickAwayListener
          mouseEvent="onMouseDown"
          touchEvent="onTouchStart"
          onClickAway={() => setAnchor(null)}
        >
          <Paper
            role="dialog"
            onSubmit={() => setAnchor(null)}
            aria-label={t('recordingManual')}
            sx={{ p: 2, maxWidth: 'min(34rem, calc(100vw - 2rem))' }}
            onKeyDown={(event) => {
              if (event.key === 'Escape') {
                setAnchor(null);
                anchor?.focus({ preventScroll: true });
              }
            }}
          >
            {controls.openByID}
          </Paper>
        </ClickAwayListener>
      </Popper>
    </Toolbar>
  );
}
