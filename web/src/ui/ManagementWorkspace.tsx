import { Tab, Tabs } from '@mui/material';
import { lazy, Suspense, useCallback, useId, useState } from 'react';
import type { WebAccess } from '../remember';
import { accessMessages } from './access-messages';
import { Alert, Button } from './material';
import { t } from './messages';
import { useAccessStatus } from './use-access-status';

const ManagementPanel = lazy(async () => ({
  default: (await import('../management/ManagementPanel')).ManagementPanel,
}));
const ArtifactPanel = lazy(async () => ({
  default: (await import('../artifacts/ArtifactPanel')).ArtifactPanel,
}));

// One fixed access per mounted management tab. Switching or adding unrelated
// connections must neither rebind this view nor destroy its local evidence.
export function ManagementWorkspace({
  access,
  owner,
  active,
  disabled,
  onActionLock,
  onReauthenticate,
  reauthenticationBlocked = false,
}: {
  access: WebAccess;
  owner: number;
  active: boolean;
  disabled: boolean;
  onActionLock: (owner: number, locked: boolean) => void;
  onReauthenticate: () => void;
  reauthenticationBlocked?: boolean;
}) {
  const [view, setView] = useState<'sessions' | 'artifacts' | 'server'>('sessions');
  const navigationID = useId();
  const [locked, setLocked] = useState(false);
  const status = useAccessStatus(access);
  const remoteDisabled = status !== 'active';
  const lock = useCallback(
    (value: boolean) => {
      setLocked(value);
      if (value) {
        setView('sessions');
      }
      onActionLock(owner, value);
    },
    [onActionLock, owner],
  );
  return (
    <>
      {remoteDisabled && (
        <Alert
          color="yellow"
          action={
            <Button
              variant="subtle"
              disabled={disabled || locked || reauthenticationBlocked || !active}
              onClick={() => {
                if (!disabled && !locked && !reauthenticationBlocked && active) {
                  onReauthenticate();
                }
              }}
            >
              {accessMessages.reauthenticate}
            </Button>
          }
        >
          {status === 'expired' ? accessMessages.expiredNotice : accessMessages.closedNotice}
        </Alert>
      )}
      <nav className="workspace-tabs" aria-label={t('workspaceNavigation')}>
        <Tabs
          value={view}
          variant="scrollable"
          scrollButtons="auto"
          allowScrollButtonsMobile
          aria-label={t('workspaceNavigation')}
          onChange={(_event, next) => {
            if (!disabled && !locked && ['sessions', 'artifacts', 'server'].includes(next)) {
              setView(next);
            }
          }}
        >
          {(['sessions', 'artifacts', 'server'] as const).map((item) => (
            <Tab
              key={item}
              value={item}
              id={`${navigationID}-${item}`}
              aria-controls={`${navigationID}-${item === 'artifacts' ? 'artifacts' : 'management'}-panel`}
              disabled={disabled || locked}
              label={t(
                item === 'sessions'
                  ? 'workspaceSessions'
                  : item === 'artifacts'
                    ? 'workspaceArtifacts'
                    : 'workspaceServer',
              )}
            />
          ))}
        </Tabs>
      </nav>
      <Suspense fallback={<Alert>{t('managementLoading')}</Alert>}>
        <div
          hidden={view === 'artifacts'}
          role="tabpanel"
          id={`${navigationID}-management-panel`}
          aria-labelledby={`${navigationID}-${view === 'server' ? 'server' : 'sessions'}`}
        >
          <ManagementPanel
            access={access}
            active={active && view !== 'artifacts'}
            disabled={disabled || remoteDisabled}
            onActionLock={lock}
            view={view === 'server' ? 'server' : 'sessions'}
          />
        </div>
        <div
          hidden={view !== 'artifacts'}
          role="tabpanel"
          id={`${navigationID}-artifacts-panel`}
          aria-labelledby={`${navigationID}-artifacts`}
        >
          <ArtifactPanel
            access={access}
            disabled={disabled || locked}
            remoteDisabled={remoteDisabled}
            active={active && view === 'artifacts'}
          />
        </div>
      </Suspense>
    </>
  );
}
