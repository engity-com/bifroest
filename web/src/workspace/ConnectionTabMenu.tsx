import CloseIcon from '@mui/icons-material/Close';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import KeyboardReturnIcon from '@mui/icons-material/KeyboardReturn';
import LinkOffIcon from '@mui/icons-material/LinkOff';
import LogoutIcon from '@mui/icons-material/Logout';
import PowerSettingsNewIcon from '@mui/icons-material/PowerSettingsNew';
import RefreshIcon from '@mui/icons-material/Refresh';
import SettingsIcon from '@mui/icons-material/Settings';
import StopIcon from '@mui/icons-material/Stop';
import type { ReactNode } from 'react';
import type { TerminalState } from '../terminal/socket';
import { Menu } from '../ui/material';
import { t } from '../ui/messages';

export interface ConnectionMenuView {
  principal: string;
  slug: string;
  kind: 'terminal' | 'management';
  phase: TerminalState['phase'];
  inputClosed: boolean;
}

// Keep the Menu and its direct items together: MUI owns keyboard focus/selection.
// This view receives no access grant, socket, cancellation handle or mutable tab.
export function ConnectionTabMenu({
  owner,
  blocked,
  focusBlocked,
  atLimit,
  onChange,
  actions,
  children,
}: {
  owner: ConnectionMenuView | null;
  blocked: boolean;
  focusBlocked: boolean;
  atLimit: boolean;
  onChange(opened: boolean): void;
  actions: {
    duplicate(): void;
    reauthenticate(): void;
    copyLink(): void;
    settings(): void;
    eof(): void;
    signal(value: 'INT' | 'TERM'): void;
    disconnect(): void;
    logout(): void;
    close(): void;
  };
  children: ReactNode;
}) {
  return (
    <Menu opened={owner !== null} onChange={onChange} returnFocus={false}>
      {children}
      <Menu.Dropdown aria-label={t('connectionTabMenu')}>
        {owner && (
          <>
            <Menu.Label>
              {owner.principal}
              {owner.slug ? ` · ${owner.slug}` : ''}
            </Menu.Label>
            <Menu.Item
              icon={<ContentCopyIcon fontSize="small" />}
              disabled={blocked || focusBlocked || atLimit}
              onClick={actions.duplicate}
            >
              {t('connectionDuplicate')}
            </Menu.Item>
            <Menu.Item
              icon={<RefreshIcon fontSize="small" />}
              disabled={blocked || focusBlocked || atLimit}
              onClick={actions.reauthenticate}
            >
              {t('reauthenticate')}
            </Menu.Item>
            <Menu.Item
              icon={<ContentCopyIcon fontSize="small" />}
              disabled={blocked || focusBlocked}
              onClick={actions.copyLink}
            >
              {t('connectionCopyPermanentLink')}
            </Menu.Item>
            <Menu.Item
              icon={<SettingsIcon fontSize="small" />}
              disabled={blocked || owner.phase !== 'connected'}
              onClick={actions.settings}
            >
              {t('connectionSettings')}
            </Menu.Item>
            {owner.kind === 'terminal' && (
              <>
                <Menu.Divider />
                <Menu.Label>{t('terminalSpecial')}</Menu.Label>
                <Menu.Item
                  icon={<KeyboardReturnIcon fontSize="small" />}
                  disabled={blocked || owner.phase !== 'connected' || owner.inputClosed}
                  onClick={actions.eof}
                >
                  {t('terminalEof')}
                </Menu.Item>
                <Menu.Item
                  icon={<StopIcon fontSize="small" />}
                  disabled={blocked || owner.phase !== 'connected'}
                  onClick={() => actions.signal('INT')}
                >
                  {t('terminalInterrupt')}
                </Menu.Item>
                <Menu.Item
                  icon={<PowerSettingsNewIcon fontSize="small" />}
                  disabled={blocked || owner.phase !== 'connected'}
                  onClick={() => actions.signal('TERM')}
                >
                  {t('terminalTerminate')}
                </Menu.Item>
                <Menu.Item
                  icon={<LinkOffIcon fontSize="small" />}
                  disabled={blocked || !['connecting', 'connected'].includes(owner.phase)}
                  onClick={actions.disconnect}
                >
                  {t('terminalDisconnect')}
                </Menu.Item>
              </>
            )}
            <Menu.Divider />
            <Menu.Item
              icon={<LogoutIcon fontSize="small" />}
              disabled={blocked || focusBlocked}
              onClick={actions.logout}
            >
              {t('logout')}
            </Menu.Item>
            <Menu.Item
              icon={<CloseIcon fontSize="small" />}
              color="red"
              disabled={blocked || focusBlocked}
              onClick={actions.close}
            >
              {t('close')}
            </Menu.Item>
          </>
        )}
      </Menu.Dropdown>
    </Menu>
  );
}
