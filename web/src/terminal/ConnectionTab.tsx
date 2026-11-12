import CircleIcon from '@mui/icons-material/Circle';
import CloseIcon from '@mui/icons-material/Close';
import type { TabProps } from '@mui/material';
import { Box, IconButton, Tab, Tooltip } from '@mui/material';
import { forwardRef, type KeyboardEvent, type MouseEvent } from 'react';
import type { WebAccess } from '../remember';
import { accessMessages } from '../ui/access-messages';
import { Menu } from '../ui/material';
import { t } from '../ui/messages';
import { useAccessStatus } from '../ui/use-access-status';
import type { TerminalState } from './socket';

type Props = Omit<TabProps, 'id' | 'onSelect'> & {
    id: number;
    value: number;
    href?: string;
    principal: string;
    title?: string;
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
// Titles are display metadata; the verified principal stays separate in ARIA/tooltip.
export const ConnectionTab = forwardRef<HTMLDivElement, Props>(function ConnectionTab(
    {
        id,
        principal,
        title,
        scope,
        kind,
        access,
        state,
        active,
        onSelect,
        onMenu,
        onClose,
        ...props
    },
    ref,
) {
    const status = useAccessStatus(access, kind === 'management');
    const phase = kind === 'terminal' ? state.phase : status === 'active' ? 'connected' : status;
    const accessLabel =
        kind === 'management' && status !== 'active' ? accessMessages[status] : null;
    return (
        <Menu.ContextMenu onOpen={() => onMenu(true)}>
            <Tab
                {...props}
                ref={ref}
                component={props.href ? 'a' : 'div'}
                id={`terminal-tab-${id}`}
                aria-controls={`terminal-pane-${id}`}
                aria-label={`${t(kind === 'terminal' ? 'terminalTitle' : 'workspaceManagement')} ${id} ${principal}${accessLabel ? ` · ${accessLabel} · ${accessMessages.reauthenticate}` : ''}`}
                data-access-status={kind === 'management' ? status : undefined}
                aria-selected={active}
                aria-haspopup="menu"
                onClick={(event: MouseEvent<HTMLElement>) => {
                    if (props.disabled) {
                        event.preventDefault();
                        return;
                    }
                    if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) {
                        return;
                    }
                    event.preventDefault();
                    onSelect();
                }}
                onMouseDown={(event: MouseEvent<HTMLElement>) => {
                    if (event.button === 1) {
                        event.preventDefault();
                    }
                }}
                onAuxClick={(event: MouseEvent<HTMLElement>) => {
                    if (event.button === 1) {
                        event.preventDefault();
                        event.stopPropagation();
                        if (!props.disabled) {
                            onClose();
                        }
                    }
                }}
                onKeyDown={(event: KeyboardEvent<HTMLElement>) => {
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
                            title,
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
                            sx={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 1,
                                minWidth: 0,
                                maxWidth: '100%',
                                width: '100%',
                            }}
                        >
                            <CircleIcon
                                sx={{
                                    fontSize: 9,
                                    flexShrink: 0,
                                    color:
                                        phase === 'connected'
                                            ? 'success.main'
                                            : phase === 'connecting' ||
                                                phase === 'finishing' ||
                                                phase === 'expired'
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
                                    minWidth: 0,
                                    flex: '1 1 auto',
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap',
                                }}
                            >
                                {title ||
                                    access.snapshot().flow?.title ||
                                    t(
                                        kind === 'management'
                                            ? 'workspaceOverview'
                                            : 'terminalTitle',
                                    )}
                            </Box>
                            {accessLabel && (
                                <Box
                                    component="span"
                                    sx={{ fontSize: '0.75rem', color: 'text.secondary' }}
                                >
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
                                sx={{ flexShrink: 0 }}
                                onFocus={(event) => event.stopPropagation()}
                                onMouseDown={(event) => event.preventDefault()}
                                onClick={(event) => {
                                    event.preventDefault();
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
