import { ActionIcon, Menu, UnstyledButton } from '@mantine/core';
import type { KeyboardEvent } from 'react';
import { t } from '../ui/messages';
import type { TerminalState } from './socket';

export function ConnectionTab({
  id,
  kind,
  scope,
  principal,
  state,
  inputClosed,
  active,
  disabled,
  full,
  opened,
  onSelect,
  onMenu,
  onKeyboard,
  onDuplicate,
  onClose,
  onLogout,
  onRenew,
  onEof,
  onSignal,
  onDisconnect,
}: {
  id: number;
  kind: 'terminal' | 'management';
  scope: string;
  principal: string;
  state: TerminalState;
  inputClosed: boolean;
  active: boolean;
  disabled: boolean;
  full: boolean;
  opened: boolean;
  onSelect: () => void;
  onMenu: (open: boolean) => void;
  onKeyboard: (event: KeyboardEvent) => void;
  onDuplicate: () => void;
  onClose: () => void;
  onLogout: () => void;
  onRenew: () => void;
  onEof: () => void;
  onSignal: (signal: 'INT' | 'TERM') => void;
  onDisconnect: () => void;
}) {
  return (
    <Menu
      opened={opened}
      onChange={onMenu}
      position="bottom-start"
      returnFocus={false}
      transitionProps={{ duration: 0 }}
    >
      <Menu.ContextMenu>
        <div className="connection-tab" data-active={active || undefined}>
          <UnstyledButton
            id={`terminal-tab-${id}`}
            role="tab"
            aria-label={`${t(kind === 'terminal' ? 'terminalTitle' : 'workspaceManagement')} ${id} ${principal}`}
            aria-describedby={`connection-scope-${id}`}
            aria-controls={`terminal-pane-${id}`}
            aria-selected={active}
            aria-haspopup="menu"
            aria-expanded={opened}
            tabIndex={active ? 0 : -1}
            disabled={disabled}
            title={`${scope || '/'} · ${principal} · ${kind === 'terminal' ? t('terminalTitle') : t('workspaceManagement')} ${id}`}
            onClick={(event) => {
              event.stopPropagation();
              onSelect();
            }}
            onKeyDown={(event) => {
              if (event.key === 'ContextMenu' || (event.shiftKey && event.key === 'F10')) {
                event.preventDefault();
                event.stopPropagation();
                if (!disabled) {
                  const bounds = event.currentTarget.getBoundingClientRect();
                  event.currentTarget.dispatchEvent(
                    new MouseEvent('contextmenu', {
                      bubbles: true,
                      cancelable: true,
                      clientX: bounds.left,
                      clientY: bounds.bottom,
                    }),
                  );
                }
              } else {
                onKeyboard(event);
              }
            }}
          >
            <span
              className={`connection-dot connection-dot--${kind === 'terminal' ? state.phase : 'connected'}`}
            />
            <span id={`connection-scope-${id}`} className="tab-scope">
              {scope || '/'}
            </span>
            <span className="tab-owner">{principal}</span>
            {kind === 'management' && <span className="tab-kind">{t('workspaceManagement')}</span>}
          </UnstyledButton>
          <ActionIcon
            variant="subtle"
            color="gray"
            size="xs"
            className="connection-tab-close"
            aria-label={`${t(kind === 'terminal' ? 'terminalCloseTab' : 'managementCloseTab')} ${id}`}
            disabled={disabled}
            onClick={(event) => {
              event.stopPropagation();
              onClose();
            }}
          >
            ×
          </ActionIcon>
        </div>
      </Menu.ContextMenu>
      <Menu.Dropdown aria-label={t('connectionTabMenu')}>
        <Menu.Label>
          {scope || '/'} · {principal}
        </Menu.Label>
        <Menu.Item disabled={disabled || full} onClick={onDuplicate}>
          {t('connectionDuplicate')}
        </Menu.Item>
        <Menu.Item disabled={disabled || full} onClick={onRenew}>
          {t('reauthenticate')}
        </Menu.Item>
        {kind === 'terminal' && opened && (
          <Menu.Sub closeDelay={150}>
            <Menu.Sub.Target>
              <Menu.Sub.Item disabled={disabled}>{t('terminalSpecial')}</Menu.Sub.Item>
            </Menu.Sub.Target>
            <Menu.Sub.Dropdown>
              <Menu.Item
                disabled={disabled || state.phase !== 'connected' || inputClosed}
                onClick={onEof}
              >
                {t('terminalEof')}
              </Menu.Item>
              <Menu.Item
                disabled={disabled || state.phase !== 'connected'}
                onClick={() => onSignal('INT')}
              >
                {t('terminalInterrupt')}
              </Menu.Item>
              <Menu.Item
                disabled={disabled || state.phase !== 'connected'}
                onClick={() => onSignal('TERM')}
              >
                {t('terminalTerminate')}
              </Menu.Item>
              <Menu.Item
                disabled={disabled || !['connecting', 'connected'].includes(state.phase)}
                onClick={onDisconnect}
              >
                {t('terminalDisconnect')}
              </Menu.Item>
            </Menu.Sub.Dropdown>
          </Menu.Sub>
        )}
        <Menu.Divider />
        <Menu.Item disabled={disabled} onClick={onLogout}>
          {t('logout')}
        </Menu.Item>
        <Menu.Item color="red" disabled={disabled} onClick={onClose}>
          {t('close')}
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}
