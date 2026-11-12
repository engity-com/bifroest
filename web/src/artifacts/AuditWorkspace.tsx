import { type ComponentType, useCallback, useContext, useEffect, useRef, useState } from 'react';
import type { WebAccess } from '../remember';
import { AdminBreadcrumbs } from '../ui/AdminBreadcrumbs';
import { GridActionsContext, type GridWork, GridWorkContext } from '../ui/GridWork';
import { bookmarkPath } from '../ui/hash-route';
import { ManagementJump } from '../ui/ManagementJump';
import { managementCrumbs } from '../ui/management-crumbs';
import type { ManagementLocation } from '../ui/management-location';
import { ManagementNavigationContext, useManagementNavigation } from '../ui/management-navigation';
import { Alert } from '../ui/material';
import { t } from '../ui/messages';
import { profileResetEvent } from '../ui/profile-reset';
import { ArtifactOpenByID } from './ArtifactOpenByID';
import { AuditCatalog } from './AuditCatalog';
import { AuditOverview } from './AuditOverview';
import { AuditSourceContext } from './AuditSourceContext';
import { AuditViewContext } from './AuditViewContext';
import type {
    ArtifactEvidenceControl,
    ArtifactEvidencePanelProps,
    ArtifactEvidenceState,
} from './evidence-view';

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
    const sourceHints = useContext(AuditSourceContext);
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
    // Retain at most one operational source page for this actor. Returning via
    // the source catalog is navigation, not a fresh heavy read or a retry.
    const overview = useRef<{ access: WebAccess; route: ManagementLocation } | null>(null);
    if (overview.current?.access !== access) {
        overview.current = null;
    }
    if (source) {
        overview.current = { access, route };
    }
    const overviewRoute = overview.current?.route;
    const overviewSource = overviewRoute?.auditlog ?? '';
    const [identity, setIdentity] = useState({ access, source, producerId: '' });
    const reportIdentity = useCallback(
        (producerId: string) => setIdentity({ access, source: overviewSource, producerId }),
        [access, overviewSource],
    );
    const producerId =
        identity.access === access && identity.source === source ? identity.producerId : '';
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
    const href =
        external?.href ??
        ((target: ManagementLocation) => bookmarkPath(access.snapshot().scope, target));
    const [mode, setMode] = useState<'overview' | 'local'>('overview');
    const [resultVisible, setResultVisible] = useState(true);
    const evidence = useRef<ArtifactEvidenceControl | null>(null);
    const [state, setState] = useState<ArtifactEvidenceState>({
        phase: null,
        progress: null,
        hasGrid: false,
        received: false,
        status: undefined,
    });
    const [details, setDetails] = useState({ access, source, value: false });
    const sensitive = details.access === access && details.source === source && details.value;
    const [forgotten, setForgotten] = useState(false);
    // biome-ignore lint/correctness/useExhaustiveDependencies: Only a newly owned access may leave the locally-forgotten state; no old grant is resumed.
    useEffect(() => {
        setForgotten(false);
        const forget = () => {
            setForgotten(true);
        };
        window.addEventListener(profileResetEvent, forget);
        return () => window.removeEventListener(profileResetEvent, forget);
    }, [access]);
    // biome-ignore lint/correctness/useExhaustiveDependencies: Actor/source boundaries retire their verification controller and local result rather than rebinding it.
    useEffect(() => {
        setMode('overview');
        setResultVisible(true);
        setState({
            phase: null,
            progress: null,
            hasGrid: false,
            received: false,
            status: undefined,
        });
    }, [access, source]);
    // Only an explicit verification's completed result may switch the source.
    // Availability/status changes must never undo a user's return to the server.
    const showLocal = useCallback(() => setMode('local'), []);
    const local = mode === 'local' && state.hasGrid;
    const work: GridWork = {
        mode:
            state.phase !== null
                ? 'cancel'
                : local || (resultVisible && state.result)
                  ? 'server'
                  : 'verify',
        disabled: disabled || !active || (!local && remoteDisabled && !state.received),
        progress: state.progress,
        status: state.status,
        result: resultVisible && state.phase === null ? state.result : undefined,
        onStatusClick: () => evidence.current?.showDetails(),
        onClick: () => {
            if (state.phase !== null) {
                evidence.current?.cancel();
            } else if (local || (resultVisible && state.result)) {
                setMode('overview');
                setResultVisible(false);
            } else {
                setResultVisible(true);
                evidence.current?.openOptions();
            }
        },
    };
    const localNavigate = (next: ManagementLocation, replace?: boolean) => {
        if (next.page === 'auditlogs' && !next.auditlog) {
            setMode('overview');
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
        <ManagementNavigationContext.Provider value={{ location: route, navigate, href }}>
            <AuditViewContext.Provider
                value={{
                    scope: access.snapshot().scope,
                    producerId,
                    sensitive,
                    toggleSensitive: () => {
                        if (active && !disabled && state.phase === null) {
                            setDetails({ access, source, value: !sensitive });
                        }
                    },
                    requestPrivate: () => {
                        if (active && !disabled && state.phase === null && source) {
                            setDetails({ access, source, value: true });
                            setResultVisible(true);
                            evidence.current?.openOptions(true);
                        }
                    },
                    local,
                    running: state.phase !== null,
                    provenance: state.status,
                }}
            >
                <GridActionsContext.Provider
                    value={
                        source
                            ? (locked) => (
                                  <ManagementJump
                                      scope={access.snapshot().scope}
                                      target={{
                                          managementFlow: route.managementFlow,
                                          page: 'recordings',
                                          auditlogHint: source,
                                          ...(route.flow ? { flow: route.flow } : {}),
                                          ...(route.sessionId
                                              ? { sessionId: route.sessionId }
                                              : {}),
                                      }}
                                      compact
                                      label="workspaceRecordings"
                                      disabled={locked || disabled || !active}
                                  />
                              )
                            : undefined
                    }
                >
                    <GridWorkContext.Provider value={source ? work : undefined}>
                        <section
                            className="stack artifact-panel"
                            aria-label={t('workspaceAuditlogs')}
                            data-audit-view={local ? 'local' : 'server'}
                            data-audit-phase={state.phase ?? 'idle'}
                        >
                            {!external && (
                                <AdminBreadcrumbs
                                    items={managementCrumbs(route, navigate, disabled)}
                                />
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
                                            onAuditlog={(auditlog) =>
                                                setPin({ ...pinValue, auditlog })
                                            }
                                            onID={(event) => setPin({ ...pinValue, event })}
                                            onGo={() =>
                                                navigate({
                                                    managementFlow: route.managementFlow,
                                                    page: 'auditlogs',
                                                    auditlog: pinValue.auditlog,
                                                    ...(pinValue.event
                                                        ? { eventHint: pinValue.event }
                                                        : {}),
                                                })
                                            }
                                        />
                                    }
                                    onSelect={(request, summary) => {
                                        if (summary) {
                                            sourceHints?.select(summary);
                                        }
                                        if (summary?.producerId) {
                                            setIdentity({
                                                access,
                                                source: request.auditlog,
                                                producerId: summary.producerId,
                                            });
                                        }
                                        navigate({
                                            managementFlow: route.managementFlow,
                                            page: 'auditlogs',
                                            auditlog: request.auditlog,
                                            ...(route.flow ? { flow: route.flow } : {}),
                                            ...(route.sessionId
                                                ? { sessionId: route.sessionId }
                                                : {}),
                                        });
                                    }}
                                    onRecordings={(source) => {
                                        sourceHints?.select(source);
                                        navigate({
                                            managementFlow: route.managementFlow,
                                            page: 'recordings',
                                            auditlogHint: source.name,
                                            ...(route.flow ? { flow: route.flow } : {}),
                                            ...(route.sessionId
                                                ? { sessionId: route.sessionId }
                                                : {}),
                                        });
                                    }}
                                />
                            </div>
                            {overviewSource && overviewRoute && (
                                <div hidden={local || !source}>
                                    <ManagementNavigationContext.Provider
                                        value={{ location: overviewRoute, navigate, href }}
                                    >
                                        <AuditOverview
                                            key={`overview:${owner.current.epoch}:${overviewSource}`}
                                            access={access}
                                            source={overviewSource}
                                            onSource={reportIdentity}
                                            active={active && !local && source === overviewSource}
                                            disabled={disabled || remoteDisabled}
                                        />
                                    </ManagementNavigationContext.Provider>
                                </div>
                            )}
                            {source && (
                                <div hidden={!local}>
                                    <ManagementNavigationContext.Provider
                                        value={{ location: route, navigate: localNavigate, href }}
                                    >
                                        <Evidence
                                            key={`local:${owner.current.epoch}:${source}`}
                                            access={access}
                                            view="auditlogs"
                                            mode="audit-verification"
                                            disabled={disabled}
                                            remoteDisabled={remoteDisabled}
                                            active={active}
                                            backgroundAllowed={active}
                                            controlRef={evidence}
                                            onEvidenceState={setState}
                                            onResultReady={showLocal}
                                            hideBreadcrumbs
                                            regionLabel={t('auditLocalRegion')}
                                        />
                                    </ManagementNavigationContext.Provider>
                                </div>
                            )}
                        </section>
                    </GridWorkContext.Provider>
                </GridActionsContext.Provider>
            </AuditViewContext.Provider>
        </ManagementNavigationContext.Provider>
    );
}
