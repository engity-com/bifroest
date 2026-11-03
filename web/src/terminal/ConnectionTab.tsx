import CircleIcon from '@mui/icons-material/Circle';
import CloseIcon from '@mui/icons-material/Close';
import type { TabProps } from '@mui/material';
import { Box, IconButton, Tab, Tooltip } from '@mui/material';
import { forwardRef } from 'react';
import type { WebAccess } from '../remember';
import { accessMessages } from '../ui/access-messages';
import { Menu } from '../ui/material';
import { t } from '../ui/messages';
import { useAccessStatus } from '../ui/use-access-status';
import type { TerminalState } from './socket';

type Props = Omit<TabProps, 'id' | 'onSelect'> & {
  id: number;
  value: number;
  principal: string;
  scope: string;
  kind: 'terminal' | 'management';
  access: WebAccess;
  state: TerminalState;
  active: boolean;
  onSelect: () => void;
  onMenu: (value: boolean) => void;
  onClose: () => void;
};

// A genuine Material Tab, forwarded through MUI Tabs' selection/focus contract.
// The default visible label is the verified principal only, not URL punctuation.
export const ConnectionTab = forwardRef<HTMLDivElement, Props>(function ConnectionTab(
  { id, principal, scope, kind, access, state, active, onSelect, onMenu, onClose, ...props },
  ref,
) {
  const status = useAccessStatus(access);
  const phase = kind === 'terminal' ? state.phase : status === 'active' ? 'connected' : status;
  const accessLabel = kind === 'management' && status !== 'active' ? accessMessages[status] : null;
  return (
    <Menu.ContextMenu onOpen={() => onMenu(true)}>
      <Tab
        {...props}
        ref={ref}
        component="div"
        id={`terminal-tab-${id}`}
        aria-controls={`terminal-pane-${id}`}
        aria-label={`${t(kind === 'terminal' ? 'terminalTitle' : 'workspaceManagement')} ${id} ${principal}${accessLabel ? ` · ${accessLabel} · ${accessMessages.reauthenticate}` : ''}`}
        data-access-status={kind === 'management' ? status : undefined}
        aria-selected={active}
        aria-haspopup="menu"
        onClick={onSelect}
        onKeyDown={(event) => {
          if (event.key === 'ContextMenu' || (event.shiftKey && event.key === 'F10')) {
            event.preventDefault();
            event.stopPropagation();
            const bounds = event.currentTarget.getBoundingClientRect();
            if (!props.disabled) {
              event.currentTarget.dispatchEvent(
                new MouseEvent('contextmenu', {
                  bubbles: true,
                  cancelable: true,
                  clientX: bounds.left,
                  clientY: bounds.bottom,
                }),
              );
            }
          }
        }}
        label={
          <Tooltip
            title={[
              principal,
              scope || undefined,
              `${t(kind === 'terminal' ? 'terminalTitle' : 'workspaceManagement')} ${id}`,
              accessLabel ?? phase,
              accessLabel ? accessMessages.reauthenticate : undefined,
            ]
              .filter(Boolean)
              .join(' · ')}
          >
            <Box
              component="span"
              sx={{ display: 'inline-flex', alignItems: 'center', gap: 1, minWidth: 0 }}
            >
              <CircleIcon
                sx={{
                  fontSize: 9,
                  color:
                    phase === 'connected'
                      ? 'success.main'
                      : phase === 'connecting' || phase === 'finishing' || phase === 'expired'
                        ? 'warning.main'
                        : phase === 'interrupted'
                          ? 'error.main'
                          : 'text.disabled',
                }}
              />
              <Box
                component="span"
                sx={{
                  maxWidth: 160,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {principal}
              </Box>
              {accessLabel && (
                <Box component="span" sx={{ fontSize: '0.75rem', color: 'text.secondary' }}>
                  {accessLabel}
                </Box>
              )}
              {/* Closing a background execution must not first select its Tab. */}
              <IconButton
                size="small"
                component="span"
                role="button"
                tabIndex={-1}
                aria-label={`${t(kind === 'terminal' ? 'terminalCloseTab' : 'managementCloseTab')} ${id}`}
                disabled={props.disabled}
                onFocus={(event) => event.stopPropagation()}
                onMouseDown={(event) => event.preventDefault()}
                onClick={(event) => {
                  event.stopPropagation();
                  onClose();
                }}
              >
                <CloseIcon sx={{ fontSize: 16 }} />
              </IconButton>
            </Box>
          </Tooltip>
        }
      />
    </Menu.ContextMenu>
  );
});
