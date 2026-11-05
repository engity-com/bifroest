import FilterListIcon from '@mui/icons-material/FilterList';
import PushPinIcon from '@mui/icons-material/PushPin';
import RefreshIcon from '@mui/icons-material/Refresh';
import SearchIcon from '@mui/icons-material/Search';
import VisibilityIcon from '@mui/icons-material/Visibility';
import VisibilityOffIcon from '@mui/icons-material/VisibilityOff';
import { Box, ClickAwayListener, Paper, Popper, Tooltip } from '@mui/material';
import {
  FilterPanelTrigger,
  QuickFilter,
  QuickFilterControl,
  QuickFilterTrigger,
  Toolbar,
  ToolbarButton,
} from '@mui/x-data-grid';
import { createContext, type ReactNode, useContext, useEffect, useState } from 'react';
import { setDetailedView, useDetailedView } from './detail-preference';
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
}
export const AdminGridControlsContext = createContext<AdminGridControls | null>(null);
export function AdminGridToolbar() {
  const controls = useContext(AdminGridControlsContext);
  const detailed = useDetailedView();
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  useEffect(() => {
    if (!controls?.active || controls.disabled) {
      setAnchor(null);
    }
  }, [controls?.active, controls?.disabled]);
  if (!controls) {
    return null;
  }
  const locked = controls.busy || controls.disabled || !controls.active;
  return (
    <Toolbar aria-label={t('adminGridToolbar')}>
      <Box sx={{ flex: 1 }} />
      <Tooltip title={controls.refreshLabel ?? t('adminGridRefresh')}>
        <span>
          <ToolbarButton
            aria-label={controls.refreshLabel ?? t('adminGridRefresh')}
            disabled={locked || !controls.onRefresh}
            onClick={controls.onRefresh}
          >
            <RefreshIcon fontSize="small" />
          </ToolbarButton>
        </span>
      </Tooltip>
      <Tooltip title={t('adminGridDetails')}>
        <span>
          <ToolbarButton
            aria-label={t('adminGridDetails')}
            aria-pressed={controls.detailsAvailable && detailed}
            disabled={locked || !controls.detailsAvailable}
            onClick={() => setDetailedView(!detailed)}
          >
            {controls.detailsAvailable && detailed ? (
              <VisibilityIcon fontSize="small" />
            ) : (
              <VisibilityOffIcon fontSize="small" />
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
          <FilterPanelTrigger
            render={
              <ToolbarButton
                aria-label="Filters"
                disabled={controls.disabled || !controls.active}
              />
            }
          >
            <FilterListIcon fontSize="small" />
          </FilterPanelTrigger>
        </Tooltip>
      )}
      {controls.filterable && (
        <QuickFilter>
          <QuickFilterTrigger
            render={
              <ToolbarButton aria-label="Search" disabled={controls.disabled || !controls.active} />
            }
          >
            <SearchIcon fontSize="small" />
          </QuickFilterTrigger>
          <QuickFilterControl
            placeholder="Search…"
            className={(state) =>
              state.expanded ? 'admin-quick-filter' : 'admin-quick-filter-hidden'
            }
            disabled={controls.disabled || !controls.active}
          />
        </QuickFilter>
      )}
      <Popper
        open={controls.active && anchor !== null}
        anchorEl={anchor}
        placement="bottom-end"
        sx={{ zIndex: 1300 }}
      >
        <ClickAwayListener onClickAway={() => setAnchor(null)}>
          <Paper
            role="dialog"
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
