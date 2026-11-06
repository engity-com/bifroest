import { type ComponentType, useEffect, useRef, useState } from 'react';
import type { WebAccess } from '../remember';
import { AdminBreadcrumbs } from '../ui/AdminBreadcrumbs';
import type { ManagementLocation } from '../ui/management-location';
import { ManagementNavigationContext, useManagementNavigation } from '../ui/management-navigation';
import { Alert, Button } from '../ui/material';
import { t } from '../ui/messages';
import { profileResetEvent } from '../ui/profile-reset';
import { ArtifactOpenByID } from './ArtifactOpenByID';
import type { ArtifactEvidencePanelProps } from './ArtifactPanel';
import { AuditCatalog } from './AuditCatalog';
import { AuditOverview } from './AuditOverview';
import { VerifyAllButton } from './VerifyAllButton';

export function AuditWorkspace({
  access,
  disabled,
  remoteDisabled = false,
  active = true,
  Evidence,
}: {
  access: WebAccess;
  disabled: boolean;
  remoteDisabled?: boolean;
  active?: boolean;
  Evidence: ComponentType<ArtifactEvidencePanelProps>;
}) {
  const external = useManagementNavigation();
  const owner = useRef({ access, epoch: 0, route: null as ManagementLocation | null });
  if (owner.current.access !== access) {
    owner.current = { access, epoch: owner.current.epoch + 1, route: null };
  }
  if (external?.location.page === 'auditlogs') {
    owner.current.route = external.location;
  }
  const root: ManagementLocation = {
    managementFlow: access.snapshot().flow?.name ?? 'management',
    page: 'auditlogs',
  };
  const [legacy, setLegacy] = useState({ access, route: root });
  const route = external
    ? (owner.current.route ?? {
        managementFlow: external.location.managementFlow,
        page: 'auditlogs' as const,
      })
    : (owner.current.route ?? (legacy.access === access ? legacy.route : root));
  const source = route.auditlog ?? '';
  const [pin, setPin] = useState({ access, auditlog: '', event: '' });
  const pinValue = pin.access === access ? pin : { access, auditlog: '', event: '' };
  const navigate = (next: ManagementLocation, replace?: boolean) => {
    if (external) {
      external.navigate(next, replace);
    } else {
      owner.current.route = next;
      setLegacy({ access, route: next });
    }
  };
  const [mode, setMode] = useState<'overview' | 'local'>('overview');
  const [nonce, setNonce] = useState(0);
  const [phase, setPhase] = useState<string | null>(null);
  const [cancelRevision, setCancelRevision] = useState(0);
  const verification = useRef<{
    access: WebAccess;
    source: string;
  } | null>(null);
  const [forgotten, setForgotten] = useState(false);
  // biome-ignore lint/correctness/useExhaustiveDependencies: Only a newly owned access may leave the locally-forgotten state; no old grant is resumed.
  useEffect(() => {
    setForgotten(false);
    const forget = () => {
      verification.current = null;
      setForgotten(true);
      setNonce(0);
      setPhase(null);
    };
    window.addEventListener(profileResetEvent, forget);
    return () => window.removeEventListener(profileResetEvent, forget);
  }, [access]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: Actor/source boundaries retire their verification controller and local result rather than rebinding it.
  useEffect(() => {
    setMode('overview');
    setNonce(0);
    setPhase(null);
    return () => {
      verification.current = null;
    };
  }, [access, source]);
  const local =
    verification.current?.access === access && verification.current.source === source && nonce > 0;
  function verify(selected: string) {
    if (!active || disabled || remoteDisabled || selected !== source) {
      return;
    }
    verification.current = { access, source: selected };
    setNonce((value) => value + 1);
    setMode('local');
  }
  const localNavigate = (next: ManagementLocation, replace?: boolean) => {
    if (!next.auditlog) {
      verification.current = null;
      setNonce(0);
      setMode('overview');
      setPhase(null);
      return;
    }
    navigate(next, replace);
  };
  if (forgotten) {
    return (
      <section aria-label={t('workspaceAuditlogs')}>
        <Alert>{t('auditOverviewForgotten')}</Alert>
      </section>
    );
  }
  return (
    <ManagementNavigationContext.Provider value={{ location: route, navigate }}>
      <section className="stack artifact-panel" aria-label={t('workspaceAuditlogs')}>
        {!external && (
          <AdminBreadcrumbs
            items={[
              { label: t('workspaceBifroest') },
              {
                label: t('workspaceAuditlogs'),
                ...(source
                  ? {
                      onClick: () =>
                        navigate({ managementFlow: route.managementFlow, page: 'auditlogs' }),
                    }
                  : {}),
              },
              ...(source ? [{ label: source }] : []),
            ]}
          />
        )}
        <div className="actions">
          <VerifyAllButton
            source={source}
            kind="audit"
            disabled={disabled || remoteDisabled || !active || phase !== null}
            onConfirm={verify}
          />
          {source && (
            <>
              <Button
                variant={mode === 'overview' ? 'light' : 'subtle'}
                onClick={() => setMode('overview')}
              >
                {t('auditOverviewMode')}
              </Button>
              <Button
                variant={mode === 'local' ? 'light' : 'subtle'}
                disabled={!local}
                onClick={() => setMode('local')}
              >
                {t('auditLocalMode')}
              </Button>
            </>
          )}
          {phase !== null && mode === 'overview' && (
            <Button variant="default" onClick={() => setCancelRevision((value) => value + 1)}>
              {t('verifyAllCancel')}
            </Button>
          )}
        </div>
        {phase !== null && mode === 'overview' && (
          <Alert color="blue" role="status">
            {t('auditLocalRunning')}
          </Alert>
        )}
        <div hidden={source !== ''}>
          <AuditCatalog
            key={`catalog:${owner.current.epoch}`}
            access={access}
            disabled={disabled || remoteDisabled}
            active={active && source === ''}
            openByID={
              <ArtifactOpenByID
                view="auditlogs"
                auditlog={pinValue.auditlog}
                id={pinValue.event}
                disabled={disabled || remoteDisabled}
                onAuditlog={(auditlog) => setPin({ ...pinValue, auditlog })}
                onID={(event) => setPin({ ...pinValue, event })}
                onGo={() =>
                  navigate({
                    managementFlow: route.managementFlow,
                    page: 'auditlogs',
                    auditlog: pinValue.auditlog,
                    ...(pinValue.event ? { eventHint: pinValue.event } : {}),
                  })
                }
              />
            }
            onSelect={(request) =>
              navigate({
                managementFlow: route.managementFlow,
                page: 'auditlogs',
                auditlog: request.auditlog,
              })
            }
          />
        </div>
        {source && (
          <div hidden={mode !== 'overview'}>
            <AuditOverview
              key={`overview:${owner.current.epoch}:${source}`}
              access={access}
              source={source}
              active={active && mode === 'overview'}
              disabled={disabled || remoteDisabled}
            />
          </div>
        )}
        {local && (
          <div hidden={mode !== 'local'}>
            <ManagementNavigationContext.Provider
              value={{ location: route, navigate: localNavigate }}
            >
              <Evidence
                key={`local:${owner.current.epoch}:${source}:${nonce}`}
                access={access}
                view="auditlogs"
                disabled={disabled}
                remoteDisabled={remoteDisabled}
                active={active && mode === 'local'}
                backgroundAllowed={active && mode === 'overview'}
                verificationCancel={cancelRevision}
                onPhaseChange={setPhase}
                hideBreadcrumbs
                regionLabel={t('auditLocalRegion')}
              />
            </ManagementNavigationContext.Provider>
          </div>
        )}
      </section>
    </ManagementNavigationContext.Provider>
  );
}
