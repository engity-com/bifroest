import type { ReactNode } from 'react';
import { useContext, useEffect, useEffectEvent, useMemo, useRef, useState } from 'react';
import { exactFlow } from '../application/management-location';
import type { ReadProgress as Progress } from '../management/progress';
import type {
    AuditlogSummary,
    ColumnFilter,
    Page,
    RecordingOptions,
    RecordingSummary,
} from '../management/protocol';
import type { WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { CursorPages } from '../shared/cursor-pages';
import { AdminDataGrid } from '../ui/AdminDataGrid';
import { useDetailedView } from '../ui/detail-preference';
import { reportUiError } from '../ui/error-report';
import { ManagementJump, relationID, sessionRelation } from '../ui/ManagementJump';
import { useManagementNavigation } from '../ui/management-navigation';
import { Alert, Button } from '../ui/material';
import type { Message } from '../ui/messages';
import { t } from '../ui/messages';
import { useOwnerKey } from '../ui/use-owner-key';
import { AuditSourceContext } from './AuditSourceContext';
import type { ArtifactRequest } from './protocol';
import { RecordingVerificationDialogs } from './RecordingVerificationDialogs';
import { type LocalRecordingIndex, localRecordingPage } from './recording-index';
import { ArtifactSecretsBoundary } from './session-secrets';
import { useRecordingVerification } from './use-recording-verification';

const when = (value: Date) =>
    new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(value);
function duration(seconds: number): string {
    const rounded = Math.round(seconds);
    if (rounded >= 3600) {
        return `${Math.floor(rounded / 3600)} h ${Math.floor(rounded / 60) % 60} min`;
    }
    if (rounded >= 60) {
        return `${Math.floor(rounded / 60)} min ${rounded % 60} s`;
    }
    return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(seconds)} s`;
}
function bytes(size: number): string {
    const unit = size >= 1024 ** 2 ? 'MiB' : size >= 1024 ? 'KiB' : 'B';
    const divisor = unit === 'MiB' ? 1024 ** 2 : unit === 'KiB' ? 1024 : 1;
    return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(size / divisor)} ${unit}`;
}

interface ArtifactCatalogProps {
    access: WebAccess;
    disabled: boolean;
    active?: boolean;
    ownerActive?: boolean;
    selected?: ArtifactRequest | null;
    onSelect(request: ArtifactRequest, summary?: RecordingSummary): void;
    openByID?: ReactNode;
    onSource?: (name: string) => void;
    onVerificationIndex?: (index: LocalRecordingIndex | null) => void;
}
export function ArtifactCatalog(props: ArtifactCatalogProps) {
    const ownerKey = useOwnerKey(props.access);
    return (
        <ArtifactSecretsBoundary access={props.access}>
            <OwnedArtifactCatalog key={ownerKey} {...props} />
        </ArtifactSecretsBoundary>
    );
}
function OwnedArtifactCatalog({
    access,
    disabled,
    active = true,
    ownerActive,
    onSelect,
    openByID,
    onSource,
    onVerificationIndex,
}: ArtifactCatalogProps) {
    const navigation = useManagementNavigation();
    const sourceHints = useContext(AuditSourceContext);
    const route = navigation?.location.page === 'recordings' ? navigation.location : null;
    const routeKey = JSON.stringify([
        route?.flow,
        route?.auditlogHint,
        route?.id,
        route?.recordingHint,
        route?.sessionId,
    ]);
    const currentRoute = useRef(routeKey);
    currentRoute.current = routeKey;
    const consumedRoute = useRef<string | null>(null);
    const loadedScope = useRef<string | null>(null);
    const nativeFilterIntent = useRef<{
        key: string;
        query: string;
        filter: ColumnFilter | null;
    } | null>(null);
    const [sources, setSources] = useState<Page<AuditlogSummary> | null>(null);
    const [sourceAccess, setSourceAccess] = useState<'pending' | 'loaded' | 'denied' | 'failed'>(
        'pending',
    );
    const [source, setSource] = useState('');
    const [rows, setRows] = useState<Page<RecordingSummary> | null>(null);
    const verification = useRecordingVerification({
        access,
        source,
        producerId:
            sources?.items.find((row) => row.name === source)?.producerId ??
            (rows?.items[0]?.auditlog === source ? rows.items[0].producerId : ''),
        active: active && (ownerActive ?? true),
        disabled,
    });
    const [page, setPage] = useState(0);
    const [query, setQuery] = useState('');
    const [sort, setSort] = useState<'asc' | 'desc'>('desc');
    const [filter, setFilter] = useState<ColumnFilter | null>(null);
    const [privateView, setPrivateView] = useState<{
        access: WebAccess;
        source: string;
        value: boolean;
        index: LocalRecordingIndex | null;
    }>({ access, source: '', value: false, index: null });
    const local =
        verification.localIndex?.source === (route?.auditlogHint ?? source)
            ? verification.localIndex
            : null;
    useEffect(() => {
        onVerificationIndex?.(local);
    }, [local, onVerificationIndex]);
    const sensitive =
        !!local &&
        (privateView.access === access &&
        privateView.source === source &&
        privateView.index === local
            ? privateView.value
            : verification.revealIndex === local);
    const localPage = useMemo(() => {
        if (!local) {
            return null;
        }
        try {
            return localRecordingPage(
                local,
                page,
                query,
                filter,
                sort === 'desc',
                sensitive,
                route?.flow,
                route?.sessionId,
            );
        } catch {
            return null;
        }
    }, [local, page, query, filter, sort, sensitive, route?.flow, route?.sessionId]);
    const [busy, setBusy] = useState(false);
    const [progress, setProgress] = useState<Progress | null>(null);
    const [failed, setFailed] = useState<Message | null>(null);
    const failedRoute = useRef<string | null>(null);
    const request = useRef<AbortController | null>(null);
    const generation = useRef(0);
    const attempted = useRef(false);
    const cursors = useRef(new CursorPages());
    const available = useRef(active && !disabled);
    available.current = active && !disabled;
    // Actor replacement is a new component lifetime, not a passive reset of
    // already-rendered metadata belonging to a previous owner.
    useEffect(() => {
        return () => {
            generation.current++;
            request.current?.abort();
            request.current = null;
        };
    }, []);
    useEffect(() => {
        if (disabled || !active) {
            request.current?.abort();
        }
    }, [disabled, active]);
    async function run(action: (signal: AbortSignal, current: number) => Promise<void>) {
        if (!active || disabled || request.current !== null) {
            return;
        }
        const controller = new AbortController();
        const current = ++generation.current;
        request.current = controller;
        setBusy(true);
        setProgress(null);
        setFailed(null);
        failedRoute.current = null;
        try {
            await action(controller.signal, current);
        } catch (error) {
            if (current === generation.current) {
                loadedScope.current = null;
                setRows(null);
                setPage(0);
                cursors.current.reset();
                if (!controller.signal.aborted) {
                    reportUiError('artifact-catalog', error);
                }
                failedRoute.current = routeKey;
                setFailed(
                    controller.signal.aborted ||
                        (error instanceof RememberMeError && error.code === 'cancelled')
                        ? 'artifactCatalogCancelled'
                        : error instanceof RememberMeError && error.code === 'denied'
                          ? 'recordingReadDenied'
                          : error instanceof RememberMeError && error.code === 'rate-limited'
                            ? 'adminReadRateLimited'
                            : 'recordingReadFailed',
                );
            }
        } finally {
            if (current === generation.current && controller.signal.aborted) {
                loadedScope.current = null;
                setRows(null);
                setPage(0);
                cursors.current.reset();
                failedRoute.current = routeKey;
                setFailed('artifactCatalogCancelled');
            }
            if (request.current === controller) {
                request.current = null;
                setBusy(false);
            }
        }
    }
    function options(
        index = 0,
        search = query,
        direction = sort,
        predicate = filter,
    ): RecordingOptions {
        return {
            after: index === 0 ? '' : (cursors.current.at(index) ?? ''),
            query: search,
            sort: direction === 'asc' ? 'started-asc' : 'started-desc',
            filter: predicate,
            ...(route?.flow ? { flow: route.flow } : {}),
            ...(route?.sessionId ? { sessionId: route.sessionId } : {}),
        };
    }
    async function load(
        name = source,
        index = 0,
        search = query,
        direction = sort,
        predicate = filter,
        remote = false,
    ) {
        if (local?.source === name && !remote) {
            if (!active || disabled) {
                return;
            }
            consumedRoute.current = routeKey;
            setPage(index);
            setQuery(search);
            setSort(direction);
            setFilter(predicate);
            return;
        }
        await run(async (signal, current) => {
            const selected = options(index, search, direction, predicate);
            consumedRoute.current = routeKey;
            loadedScope.current = null;
            setRows(null);
            setSource(name);
            setQuery(search);
            setSort(direction);
            setFilter(predicate);
            const result = await access.managementRecordings(name, selected, signal, (value) => {
                if (
                    current === generation.current &&
                    !signal.aborted &&
                    routeKey === currentRoute.current
                ) {
                    setProgress(value);
                }
            });
            if (
                current !== generation.current ||
                signal.aborted ||
                routeKey !== currentRoute.current
            ) {
                if (routeKey !== currentRoute.current && consumedRoute.current === routeKey) {
                    consumedRoute.current = null;
                }
                return;
            }
            if (index === 0) {
                cursors.current.reset();
            }
            cursors.current.completed(index, result.next);
            setSource(name);
            loadedScope.current = JSON.stringify([route?.flow, name, route?.sessionId]);
            setRows(result);
            setPage(index);
            setQuery(search);
            setSort(direction);
            setFilter(predicate);
            consumedRoute.current = routeKey;
        });
    }
    async function loadSources(after = '') {
        await run(async (signal, current) => {
            const report = (value: Progress) => {
                if (
                    current === generation.current &&
                    !signal.aborted &&
                    routeKey === currentRoute.current
                ) {
                    setProgress(value);
                }
            };
            const supplied =
                sourceHints?.access === access && sourceHints.source?.name === route?.auditlogHint
                    ? sourceHints.source
                    : null;
            const result = supplied
                ? { items: [supplied], next: '', skipped: 0 }
                : await access
                      .managementAuditlogs(
                          {
                              after,
                              ...(route?.auditlogHint
                                  ? {
                                        filter: {
                                            field: 'name',
                                            operator: 'equals',
                                            value: route.auditlogHint,
                                        },
                                    }
                                  : {}),
                          },
                          signal,
                          report,
                      )
                      .catch((error: unknown) => {
                          if (current === generation.current) {
                              setSourceAccess(
                                  !signal.aborted &&
                                      error instanceof RememberMeError &&
                                      error.code === 'denied'
                                      ? 'denied'
                                      : 'failed',
                              );
                          }
                          throw error;
                      });
            if (current !== generation.current || signal.aborted) {
                return;
            }
            const items =
                after === '' ? result.items : [...(sources?.items ?? []), ...result.items];
            setSources({ ...result, items });
            setSourceAccess('loaded');
            const enabled = items.filter((row) => row.enabled && row.recordingEnabled);
            if (
                source === '' &&
                (route?.auditlogHint || (enabled.length === 1 && result.next === ''))
            ) {
                const name = route?.auditlogHint ?? enabled[0]?.name;
                if (name === undefined) {
                    return;
                }
                setSource(name);
                if (routeKey !== currentRoute.current) {
                    return;
                }
                if (route?.id || route?.recordingHint) {
                    onSource?.(name);
                    return;
                }
                const predicate = route?.sessionId
                    ? { field: 'sessionId', operator: 'equals', value: route.sessionId }
                    : route?.flow
                      ? { field: 'flow', operator: 'equals', value: route.flow }
                      : null;
                consumedRoute.current = routeKey;
                // A source response can complete between a navigation render and its
                // passive abort effect. Do not start a new scan for an inactive page.
                if (!available.current) {
                    request.current?.abort();
                    return;
                }
                loadedScope.current = null;
                setRows(null);
                setQuery('');
                setSort('desc');
                setFilter(predicate);
                const result = await access.managementRecordings(
                    name,
                    options(0, '', 'desc', predicate),
                    signal,
                    report,
                );
                if (
                    current !== generation.current ||
                    signal.aborted ||
                    routeKey !== currentRoute.current
                ) {
                    return;
                }
                cursors.current.reset();
                cursors.current.completed(0, result.next);
                loadedScope.current = JSON.stringify([route?.flow, name, route?.sessionId]);
                setRows(result);
                setPage(0);
                setQuery('');
                setSort('desc');
                setFilter(predicate);
                consumedRoute.current = routeKey;
            }
        });
    }
    useEffect(() => {
        if (available.current && !attempted.current) {
            const current = generation.current;
            queueMicrotask(() => {
                if (current === generation.current && available.current && !attempted.current) {
                    attempted.current = true;
                    void loadSources();
                }
            });
        }
    });
    const readRoute = useEffectEvent(() => {
        // Serialize the initial source discovery before consuming the shared read
        // slot. A denied discovery may still allow the explicitly requested source
        // under a forced read ceiling; other failures never trigger a second read.
        if (
            !route ||
            !active ||
            disabled ||
            !attempted.current ||
            (sourceAccess !== 'loaded' && sourceAccess !== 'denied') ||
            busy ||
            request.current !== null ||
            (source === '' && !route.auditlogHint) ||
            consumedRoute.current === routeKey ||
            route.id ||
            route.recordingHint
        ) {
            return;
        }
        const name = route.auditlogHint ?? source;
        const native =
            nativeFilterIntent.current?.key === routeKey ? nativeFilterIntent.current : null;
        nativeFilterIntent.current = null;
        consumedRoute.current = routeKey;
        // A row/detail URL makes an automatically selected sole source explicit.
        // That spelling change is not a different dataset and must not replay its
        // retained list read after playback. A genuinely different flow/source or
        // pending native filter intent still requires an authoritative new read.
        if (
            !native &&
            rows !== null &&
            loadedScope.current === JSON.stringify([route.flow, name, route.sessionId])
        ) {
            setFailed(null);
            return;
        }
        setRows(null);
        setPage(0);
        setSource(name);
        cursors.current.reset();
        void load(
            name,
            0,
            native?.query ?? '',
            sort,
            native
                ? native.filter
                : route.sessionId
                  ? { field: 'sessionId', operator: 'equals', value: route.sessionId }
                  : route.flow
                    ? { field: 'flow', operator: 'equals', value: route.flow }
                    : exactFlow(filter)
                      ? null
                      : filter,
        );
    });
    useEffect(() => {
        if (
            request.current !== null &&
            consumedRoute.current !== null &&
            consumedRoute.current !== routeKey
        ) {
            request.current.abort();
        }
        if (
            active &&
            !disabled &&
            !busy &&
            (sourceAccess === 'loaded' || sourceAccess === 'denied') &&
            consumedRoute.current !== routeKey
        ) {
            readRoute();
        }
    }, [active, disabled, busy, routeKey, sourceAccess]);
    const locked = disabled || busy;
    const detailed = useDetailedView();
    const enabled = sources?.items.filter((row) => row.enabled && row.recordingEnabled) ?? [];
    const identity = (row: RecordingSummary) =>
        local && sensitive ? row : row.encrypted || row.metadataUnavailable ? null : row;
    const hiddenLabel = (row: RecordingSummary) =>
        local
            ? sensitive
                ? 'recordingMetadataUnknown'
                : 'recordingMetadataHidden'
            : row.encrypted
              ? 'recordingMetadataProtected'
              : 'recordingMetadataUnknown';
    const displayed = local ? (localPage ?? { items: [], next: '', skipped: 0 }) : rows;
    const privateControl =
        !!local || sources?.items.find((row) => row.name === source)?.encrypted === true;
    const gridWork = {
        ...verification.work,
        onClick: () => {
            const wasLocal = !!local && verification.work.mode === 'server';
            verification.work.onClick();
            if (wasLocal) {
                void load(source, 0, query, sort, filter, true);
            }
        },
    };
    const visibleFailure =
        local && localPage === null
            ? 'recordingReadFailed'
            : failedRoute.current === routeKey
              ? failed
              : null;
    const privateFilter = !!(
        route?.flow ||
        route?.sessionId ||
        (filter && ['flow', 'sessionId', 'user', 'target'].includes(filter.field))
    );
    const protectedScope =
        privateFilter && sources?.items.find((row) => row.name === source)?.encrypted === true;
    function showSource() {
        if (locked || !active) {
            return;
        }
        if (navigation && route) {
            const {
                flow: _flow,
                sessionId: _session,
                id: _id,
                recordingHint: _hint,
                ...parent
            } = route;
            nativeFilterIntent.current = {
                key: JSON.stringify([
                    undefined,
                    parent.auditlogHint,
                    undefined,
                    undefined,
                    undefined,
                ]),
                query: '',
                filter: null,
            };
            navigation.navigate(parent);
        } else {
            void load(source, 0, '', sort, null);
        }
    }
    return (
        <section className="stack" aria-label={t('artifactCatalog')}>
            <RecordingVerificationDialogs {...verification.dialogs} />
            {visibleFailure && (
                <Alert role="status" color="red">
                    {t(visibleFailure)}
                </Alert>
            )}
            {((sources?.skipped ?? 0) > 0 || (rows?.skipped ?? 0) > 0) && (
                <Alert color="yellow">{t('managementPartial')}</Alert>
            )}
            {sources && sources.next === '' && enabled.length === 0 && !busy && (
                <p className="empty-state">{t('recordingNoSources')}</p>
            )}
            <AdminDataGrid<RecordingSummary>
                work={gridWork}
                toolbarActions={
                    navigation && route?.auditlogHint
                        ? (locked) => (
                              <ManagementJump
                                  scope={access.snapshot().scope}
                                  target={{
                                      managementFlow: route.managementFlow,
                                      page: 'auditlogs',
                                      auditlog: route.auditlogHint ?? source,
                                      ...(route.flow ? { flow: route.flow } : {}),
                                      ...(route.sessionId ? { sessionId: route.sessionId } : {}),
                                  }}
                                  label="workspaceEvents"
                                  compact
                                  disabled={locked}
                              />
                          )
                        : undefined
                }
                readProgress={progress}
                onCancelRead={() => request.current?.abort()}
                active={active}
                actionField="open"
                label={`${t('recordingList')} · ${source}`}
                emptyState={
                    local && !sensitive && privateFilter ? (
                        <div className="stack">
                            <span>{t('auditScopeNeedsPrivateDetails')}</span>
                            <Button
                                disabled={locked || !active}
                                onClick={() =>
                                    setPrivateView({ access, source, value: true, index: local })
                                }
                            >
                                {t('adminGridShowDetails')}
                            </Button>
                        </div>
                    ) : protectedScope ? (
                        <div className="stack">
                            <span>{t('recordingEncryptedFilter')}</span>
                            <Button disabled={locked || !active} onClick={showSource}>
                                {t('recordingShowSource')}
                            </Button>
                        </div>
                    ) : undefined
                }
                resultAvailable={
                    local
                        ? localPage !== null
                        : rows !== null &&
                          (!route ||
                              loadedScope.current ===
                                  JSON.stringify([
                                      route.flow,
                                      route.auditlogHint ?? source,
                                      route.sessionId,
                                  ]))
                }
                rows={
                    localPage !== null ||
                    !route ||
                    loadedScope.current ===
                        JSON.stringify([route.flow, route.auditlogHint ?? source, route.sessionId])
                        ? (displayed?.items ?? [])
                        : []
                }
                onRefresh={() => {
                    void (source === '' ? loadSources() : load(source, page));
                }}
                refreshLabel={t('recordingRefresh')}
                openByID={openByID}
                detailsAvailable
                detailToggle={
                    privateControl
                        ? {
                              checked: sensitive,
                              showLabel: local ? 'adminGridShowDetails' : 'recordingDecryptDetails',
                              onChange: () => {
                                  if (locked || !active) {
                                      return;
                                  }
                                  if (local) {
                                      setPrivateView({
                                          access,
                                          source,
                                          value: !sensitive,
                                          index: local,
                                      });
                                  } else {
                                      verification.openPrivate();
                                  }
                              },
                          }
                        : undefined
                }
                detailed={privateControl ? sensitive : detailed}
                detailFields={['user', 'duration', 'containerBytes']}
                hiddenFields={['sessionId']}
                onOpen={(row) =>
                    onSelect({ kind: 'recording', auditlog: row.auditlog, id: row.id }, row)
                }
                openLabel={(row) => `${t('recordingOpen')} ${row.id}`}
                rowActions={(row) =>
                    navigation &&
                    identity(row) && (
                        <ManagementJump
                            scope={access.snapshot().scope}
                            target={sessionRelation(
                                navigation.location.managementFlow,
                                row.flow,
                                row.sessionId,
                            )}
                            label="showSession"
                            compact
                            disabled={locked}
                        />
                    )
                }
                columns={[
                    { field: 'id', headerName: t('artifactRecordingID'), minWidth: 270 },
                    {
                        field: 'sessionId',
                        headerName: t('managementSessionId'),
                        minWidth: 280,
                        valueGetter: (_value, row) => identity(row)?.sessionId ?? '',
                        renderCell: (params) =>
                            identity(params.row)?.sessionId || t(hiddenLabel(params.row)),
                    },
                    {
                        field: 'startedAt',
                        headerName: t('recordingStarted'),
                        minWidth: 190,
                        flex: 1,
                        type: 'dateTime',
                        valueGetter: (_value, row) => new Date(row.startedAt),
                        valueFormatter: (value) => when(value as Date),
                    },
                    {
                        field: 'user',
                        headerName: t('recordingIdentity'),
                        minWidth: 170,
                        flex: 1,
                        valueGetter: (_value, row) => identity(row)?.user ?? '',
                        renderCell: (params) => (
                            <span>
                                {identity(params.row)?.user || t(hiddenLabel(params.row))}
                                {identity(params.row)?.target && (
                                    <small>
                                        {' '}
                                        · {t('recordingFilterTarget')}:{' '}
                                        {identity(params.row)?.target}
                                    </small>
                                )}
                            </span>
                        ),
                    },
                    {
                        field: 'flow',
                        headerName: t('recordingFilterFlow'),
                        minWidth: 130,
                        valueGetter: (_value, row) => identity(row)?.flow ?? '',
                        renderCell: (params) =>
                            identity(params.row)?.flow || t(hiddenLabel(params.row)),
                    },
                    {
                        field: 'status',
                        headerName: t('recordingFilterStatus'),
                        minWidth: 130,
                        type: 'singleSelect',
                        valueOptions: [
                            { value: 'completed', label: t('artifactCatalogCompleted') },
                            { value: 'failed', label: t('artifactCatalogFailedStatus') },
                            { value: 'incomplete', label: t('artifactCatalogIncomplete') },
                        ],
                    },
                    {
                        field: 'duration',
                        headerName: t('recordingDuration'),
                        minWidth: 120,
                        type: 'number',
                        valueGetter: (_value, row) =>
                            Math.max(
                                0,
                                (Date.parse(row.endedAt) - Date.parse(row.startedAt)) / 1000,
                            ),
                        valueFormatter: (value) => duration(Number(value)),
                    },
                    {
                        field: 'containerBytes',
                        headerName: t('recordingSize'),
                        minWidth: 100,
                        type: 'number',
                        valueFormatter: (value) => bytes(Number(value)),
                    },
                ]}
                busy={busy || !attempted.current}
                disabled={disabled}
                page={page}
                hasNext={(displayed?.next ?? '') !== ''}
                total={displayed?.total}
                query={query}
                columnFilter={filter}
                sortField="startedAt"
                sortDirection={sort}
                onPage={(index) => {
                    if (local || (index <= page + 1 && cursors.current.at(index) !== undefined)) {
                        void load(source, index);
                    }
                }}
                onQuery={(value) => {
                    void load(source, 0, value);
                }}
                onSearch={(search, predicate) => {
                    const flow =
                        route?.sessionId && predicate?.field !== 'flow'
                            ? route.flow
                            : exactFlow(predicate);
                    const sessionId =
                        predicate?.field === 'sessionId'
                            ? predicate.operator === 'equals' && relationID(predicate.value)
                                ? predicate.value
                                : undefined
                            : predicate === null && filter?.field === 'sessionId'
                              ? undefined
                              : route?.sessionId;
                    if (
                        navigation &&
                        route &&
                        (flow !== route.flow || sessionId !== route.sessionId)
                    ) {
                        setQuery(search);
                        setFilter(predicate);
                        const {
                            flow: _flow,
                            id: _id,
                            recordingHint: _recording,
                            sessionId: _session,
                            ...parent
                        } = route;
                        const next = {
                            ...parent,
                            ...(flow ? { flow } : {}),
                            ...(sessionId ? { sessionId } : {}),
                        };
                        nativeFilterIntent.current = {
                            key: JSON.stringify([
                                next.flow,
                                next.auditlogHint,
                                undefined,
                                undefined,
                                next.sessionId,
                            ]),
                            query: search,
                            filter: predicate,
                        };
                        navigation.navigate(next);
                        return;
                    }
                    void load(source, 0, search, sort, predicate);
                }}
                onSort={(direction) => {
                    void load(source, 0, query, direction);
                }}
            />
        </section>
    );
}
