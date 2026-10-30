import { Alert, Button } from '@mantine/core';
import { lazy, Suspense, useCallback, useState } from 'react';
import type { WebAccess } from '../remember';
import { t } from './messages';

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
}: {
  access: WebAccess;
  owner: number;
  active: boolean;
  disabled: boolean;
  onActionLock: (owner: number, locked: boolean) => void;
}) {
  const [view, setView] = useState<'sessions' | 'artifacts' | 'server'>('sessions');
  const [locked, setLocked] = useState(false);
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
      <nav className="workspace-nav" aria-label={t('workspaceNavigation')}>
        {(['sessions', 'artifacts', 'server'] as const).map((item) => (
          <Button
            key={item}
            variant={view === item ? 'light' : 'subtle'}
            aria-current={view === item ? 'page' : undefined}
            disabled={disabled || locked}
            onClick={() => setView(item)}
          >
            {t(
              item === 'sessions'
                ? 'workspaceSessions'
                : item === 'artifacts'
                  ? 'workspaceArtifacts'
                  : 'workspaceServer',
            )}
          </Button>
        ))}
      </nav>
      <Suspense fallback={<Alert>{t('managementLoading')}</Alert>}>
        <div hidden={view === 'artifacts'}>
          <ManagementPanel
            access={access}
            active={active && view !== 'artifacts'}
            disabled={disabled}
            onActionLock={lock}
            view={view === 'server' ? 'server' : 'sessions'}
          />
        </div>
        <div hidden={view !== 'artifacts'}>
          <ArtifactPanel access={access} disabled={disabled || locked} />
        </div>
      </Suspense>
    </>
  );
}
