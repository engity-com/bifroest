import { useEffect, useEffectEvent, useRef, useState } from 'react';
import type { AuditEventItem, AuditOverviewPage } from '../management/audit-overview';
import type { ReadProgress as Progress } from '../management/progress';
import type { ColumnFilter } from '../management/protocol';
import type { WebAccess } from '../remember';
import { RememberMeError } from '../remember';
import { CursorPages } from '../shared/cursor-pages';
import { uuidEqual, uuidInputPattern } from '../shared/uuid';
import { AdminDataGrid } from '../ui/AdminDataGrid';
import { relationID } from '../ui/ManagementJump';
import { ManagementNotFound } from '../ui/ManagementNotFound';
import { exactFlow, type ManagementLocation } from '../ui/management-location';
import { useManagementNavigation } from '../ui/management-navigation';
import { Alert, Button, TextInput } from '../ui/material';
import { t } from '../ui/messages';
import { AuditEventActions, AuditEventDetails } from './AuditEventDetails';
import { useAuditView } from './AuditViewContext';

const routeFilter = (flow: string | undefined): ColumnFilter | null =>
    flow
        ? {
              field: 'flow',
              operator: flow === '-' ? 'isEmpty' : 'equals',
              value: flow === '-' ? '' : flow,
          }
        : null;
export function AuditOverview({
    access,
    source,
    active,
    disabled,
    onSource,
}: {
    access: WebAccess;
    source: string;
    active: boolean;
    disabled: boolean;
    onSource?: (producer: string) => void;
}) {
    const navigation = useManagementNavigation();
    const route = navigation?.location;
    const flow = route?.flow;
    const sessionScope = route?.sessionId;
    const view = useAuditView();
    const target = route?.id ?? route?.eventHint;
    const [rows, setRows] = useState<AuditOverviewPage | null>(null);
    const [detail, setDetail] = useState<AuditEventItem | null>(null);
    const [sourceInfo, setSourceInfo] = useState<AuditOverviewPage['source'] | null>(null);
    useEffect(() => {
        if (sourceInfo?.producerId) {
            onSource?.(sourceInfo.producerId);
        }
    }, [sourceInfo, onSource]);
    const [page, setPage] = useState(0);
    const [query, setQuery] = useState('');
    const [filter, setFilter] = useState<ColumnFilter | null>(() =>
        sessionScope
            ? { field: 'sessionId', operator: 'equals', value: sessionScope }
            : routeFilter(flow),
    );
    const [sort, setSort] = useState<'asc' | 'desc'>('desc');
    const [ownSensitive, setOwnSensitive] = useState(false);
    const sensitive = view?.sensitive ?? ownSensitive;
    const requestSensitive = sensitive && sourceInfo?.encrypted === false;
    const [busy, setBusy] = useState(false);
    const [progress, setProgress] = useState<Progress | null>(null);
    const [failed, setFailed] = useState(false);
    const [notFound, setNotFound] = useState<string | null>(null);
    const [denied, setDenied] = useState(false);
    const [rateLimited, setRateLimited] = useState(false);
    const [cancelled, setCancelled] = useState(false);
    const [refresh, setRefresh] = useState(0);
    const [eventInput, setEventInput] = useState('');
    const request = useRef<AbortController | null>(null);
    const generation = useRef(0);
    const attempted = useRef('');
    const scope = useRef(JSON.stringify([flow, sessionScope]));
    const cursors = useRef(new CursorPages());
    const cached = useRef<{ key: string; projection: string; result: AuditOverviewPage } | null>(
        null,
    );
    const native = useRef<{
        flow: string | undefined;
        query: string;
        filter: ColumnFilter | null;
    } | null>(null);
    const returnRoute = useRef<ManagementLocation | null>(null);
    const current = useRef({ flow, sessionScope, target, active, requestSensitive });
    current.current = { flow, sessionScope, target, active, requestSensitive };
    useEffect(
        () => () => {
            generation.current++;
            request.current?.abort();
        },
        [],
    );
    const reconcile = useEffectEvent(() => {
        if (!active || disabled) {
            request.current?.abort();
            return;
        }
        const scopeKey = JSON.stringify([flow, sessionScope]);
        const changed = !target && scope.current !== scopeKey;
        const intent = changed && native.current?.flow === flow ? native.current : null;
        const selectedPage = target ? 0 : changed ? 0 : page;
        const selectedQuery = target ? '' : changed ? (intent?.query ?? '') : query;
        const selectedFilter = target
            ? null
            : changed
              ? (intent?.filter ??
                (sessionScope
                    ? { field: 'sessionId', operator: 'equals', value: sessionScope }
                    : routeFilter(flow)))
              : filter;
        const key = JSON.stringify([
            source,
            flow,
            target,
            requestSensitive,
            sessionScope,
            selectedPage,
            selectedQuery,
            selectedFilter,
            sort,
            refresh,
        ]);
        const projection = JSON.stringify([
            source,
            flow,
            sessionScope,
            requestSensitive,
            sort,
            refresh,
        ]);
        if (attempted.current === key) {
            return;
        }
        if (changed) {
            scope.current = scopeKey;
            native.current = null;
            cursors.current.reset();
            setPage(0);
            setQuery(selectedQuery);
            setFilter(selectedFilter);
        }
        const token = ++generation.current;
        request.current?.abort();
        request.current = null;
        attempted.current = key;
        if (!target && cached.current?.key === key) {
            setRows(cached.current.result);
            setDetail(null);
            setBusy(false);
            setFailed(false);
            setRateLimited(false);
            setCancelled(false);
            return;
        }
        const retained =
            target && cached.current?.projection === projection
                ? cached.current.result.items.find((row) => uuidEqual(row.id, target))
                : undefined;
        if (retained) {
            setDetail(retained);
            setBusy(false);
            setFailed(false);
            setDenied(false);
            setRateLimited(false);
            setCancelled(false);
            setProgress(null);
            return;
        }
        const controller = new AbortController();
        request.current = controller;
        setBusy(true);
        setProgress(null);
        setFailed(false);
        setDenied(false);
        setRateLimited(false);
        setCancelled(false);
        setDetail(null);
        setNotFound(null);
        if (!target) {
            setRows(null);
        }
        void (async () => {
            try {
                const result = await access.managementAuditEvents(
                    source,
                    {
                        limit: target ? 1 : 20,
                        after:
                            target || selectedPage === 0
                                ? ''
                                : (cursors.current.at(selectedPage) ?? ''),
                        query: selectedQuery,
                        filter: selectedFilter,
                        sort: sort === 'desc' ? 'recorded-desc' : 'recorded-asc',
                        sensitive: requestSensitive,
                        ...(sessionScope ? { sessionId: sessionScope } : {}),
                        ...(flow ? { flow } : {}),
                        ...(target ? { id: target } : {}),
                    },
                    controller.signal,
                    (value) => {
                        if (token === generation.current && !controller.signal.aborted) {
                            setProgress(value);
                        }
                    },
                );
                if (
                    token !== generation.current ||
                    controller.signal.aborted ||
                    flow !== current.current.flow ||
                    sessionScope !== current.current.sessionScope ||
                    requestSensitive !== current.current.requestSensitive ||
                    target !== current.current.target
                ) {
                    return;
                }
                setSourceInfo(result.source);
                if (target) {
                    setDetail(result.items[0] ?? null);
                    if (result.items.length === 0) {
                        setNotFound(target);
                    }
                } else {
                    if (selectedPage === 0) {
                        cursors.current.reset();
                    }
                    cursors.current.completed(selectedPage, result.next);
                    cached.current = { key, projection, result };
                    setRows(result);
                    setPage(selectedPage);
                }
            } catch (error) {
                if (token === generation.current) {
                    setDenied(
                        !controller.signal.aborted &&
                            error instanceof RememberMeError &&
                            error.code === 'denied',
                    );
                    setFailed(!controller.signal.aborted);
                    setRateLimited(
                        !controller.signal.aborted &&
                            error instanceof RememberMeError &&
                            error.code === 'rate-limited',
                    );
                    setCancelled(controller.signal.aborted);
                    if (!target) {
                        setRows(null);
                        cursors.current.reset();
                    }
                }
            } finally {
                if (request.current === controller) {
                    request.current = null;
                }
                if (token === generation.current) {
                    setBusy(false);
                    if (controller.signal.aborted) {
                        setCancelled(true);
                    }
                }
            }
        })();
    });
    // biome-ignore lint/correctness/useExhaustiveDependencies: Effect-event reconciliation must run for each explicit route/filter/page intent, without making its internal state updates retry an RPC.
    useEffect(() => {
        reconcile();
    }, [
        active,
        disabled,
        source,
        flow,
        sessionScope,
        target,
        sensitive,
        requestSensitive,
        page,
        query,
        filter,
        sort,
        refresh,
    ]);
    const detailed = sensitive;
    const field = (row: AuditEventItem, name: string) =>
        typeof row.event[name] === 'string' ? String(row.event[name]) : '';
    function open(row: AuditEventItem) {
        if (navigation && route) {
            returnRoute.current = route;
            const { id: _id, eventHint: _event, ...parent } = route;
            navigation.navigate({ ...parent, id: row.id });
        }
    }
    return (
        <section className="stack" aria-label={t('auditOverview')}>
            {failed && (
                <Alert color="red" role="status">
                    {t(
                        denied
                            ? 'artifactDownloadDenied'
                            : rateLimited
                              ? 'adminReadRateLimited'
                              : 'auditOverviewFailed',
                    )}
                </Alert>
            )}
            {cancelled && (
                <Alert color="blue" role="status">
                    {t('artifactCatalogCancelled')}
                </Alert>
            )}
            <div hidden={!!target}>
                <AdminDataGrid<AuditEventItem>
                    active={active && !target}
                    label={t('auditEvents')}
                    rows={
                        scope.current === JSON.stringify([flow, sessionScope])
                            ? (rows?.items ?? [])
                            : []
                    }
                    resultAvailable={
                        rows !== null && scope.current === JSON.stringify([flow, sessionScope])
                    }
                    emptyState={
                        sourceInfo?.encrypted &&
                        (flow ||
                            sessionScope ||
                            (filter &&
                                ['flow', 'sessionId', 'recordingId', 'reason'].includes(
                                    filter.field,
                                ))) ? (
                            <div className="stack">
                                <span>{t('auditEncryptedFilter')}</span>
                                {view?.requestPrivate && (
                                    <Button
                                        disabled={disabled || busy || !active}
                                        onClick={view.requestPrivate}
                                    >
                                        {t('auditDecryptDetails')}
                                    </Button>
                                )}
                            </div>
                        ) : undefined
                    }
                    readProgress={progress}
                    onCancelRead={() => request.current?.abort()}
                    detailToggle={{
                        checked: sensitive,
                        onChange: () => {
                            if (sourceInfo?.encrypted) {
                                // The server cannot decrypt. Keep its completed page and open
                                // explicit local options instead of clearing an unchanged RPC.
                                if (!sensitive && view?.requestPrivate) {
                                    view.requestPrivate();
                                } else if (view) {
                                    view.toggleSensitive();
                                } else {
                                    setOwnSensitive((value) => !value);
                                }
                                return;
                            }
                            cached.current = null;
                            cursors.current.reset();
                            setPage(0);
                            setRows(null);
                            setDetail(null);
                            if (view) {
                                view.toggleSensitive();
                            } else {
                                setOwnSensitive((value) => !value);
                            }
                        },
                        disabled: !!view?.running,
                        label: 'privateDetails',
                        ...(sourceInfo?.encrypted
                            ? { showLabel: 'auditDecryptDetails' as const }
                            : {}),
                    }}
                    rowActions={(row) => (
                        <AuditEventActions
                            event={row.event}
                            scope={view?.scope}
                            sensitive={requestSensitive && rows?.source.sensitive === true}
                            compact
                            disabled={disabled || busy}
                        />
                    )}
                    getRowId={(row) => row.key}
                    busy={busy}
                    disabled={disabled}
                    page={page}
                    hasNext={(rows?.next ?? '') !== ''}
                    total={rows?.total}
                    query={query}
                    columnFilter={filter}
                    sortField="recordedAt"
                    sortDirection={sort}
                    detailsAvailable
                    detailed={detailed}
                    detailFields={['reason', 'sessionId']}
                    onOpen={open}
                    openLabel={(row) => `${t('auditEventDetails')} ${row.id}`}
                    refreshLabel={t('auditRefreshEvents')}
                    onRefresh={() => {
                        cached.current = null;
                        cursors.current.reset();
                        setPage(0);
                        setRows(null);
                        setRefresh((value) => value + 1);
                    }}
                    openByID={
                        <form
                            className="actions"
                            method="dialog"
                            onSubmit={(event) => {
                                event.preventDefault();
                                if (navigation && route) {
                                    returnRoute.current = route;
                                    const { id: _id, eventHint: _event, ...parent } = route;
                                    navigation.navigate({ ...parent, eventHint: eventInput });
                                }
                            }}
                        >
                            <TextInput
                                label={t('artifactEventID')}
                                value={eventInput}
                                onChange={(event) => setEventInput(event.currentTarget.value)}
                                required
                                maxLength={45}
                                pattern={uuidInputPattern}
                            />
                            <Button type="submit" disabled={disabled || busy || !active}>
                                Go
                            </Button>
                        </form>
                    }
                    columns={[
                        {
                            field: 'recordedAt',
                            headerName: t('auditRecordedAt'),
                            type: 'dateTime',
                            minWidth: 190,
                            valueGetter: (_value, row) => new Date(row.recordedAt),
                            valueFormatter: (value) =>
                                new Intl.DateTimeFormat(undefined, {
                                    dateStyle: 'medium',
                                    timeStyle: 'medium',
                                }).format(value as Date),
                        },
                        {
                            field: 'name',
                            headerName: t('auditEventName'),
                            minWidth: 240,
                            flex: 1,
                            valueGetter: (_value, row) => field(row, 'name'),
                        },
                        {
                            field: 'outcome',
                            headerName: t('auditEventOutcome'),
                            minWidth: 120,
                            valueGetter: (_value, row) => field(row, 'outcome'),
                        },
                        {
                            field: 'flow',
                            headerName: t('recordingFilterFlow'),
                            minWidth: 130,
                            valueGetter: (_value, row) => field(row, 'flow'),
                            renderCell: (params) =>
                                requestSensitive && rows?.source.sensitive ? (
                                    field(params.row, 'flow') || '—'
                                ) : (
                                    <span
                                        title={
                                            sourceInfo?.encrypted
                                                ? t('auditOverviewEncrypted')
                                                : undefined
                                        }
                                    >
                                        {t(
                                            sourceInfo?.encrypted
                                                ? 'auditPrivateEncrypted'
                                                : 'auditPrivateNotIncluded',
                                        )}
                                    </span>
                                ),
                        },
                        {
                            field: 'reason',
                            headerName: t('auditEventReason'),
                            minWidth: 160,
                            valueGetter: (_value, row) => field(row, 'reason'),
                            renderCell: (params) =>
                                requestSensitive && rows?.source.sensitive ? (
                                    field(params.row, 'reason')
                                ) : (
                                    <span
                                        title={
                                            sourceInfo?.encrypted
                                                ? t('auditOverviewEncrypted')
                                                : undefined
                                        }
                                    >
                                        {t(
                                            sourceInfo?.encrypted
                                                ? 'auditPrivateEncrypted'
                                                : 'auditPrivateNotIncluded',
                                        )}
                                    </span>
                                ),
                        },
                        {
                            field: 'sessionId',
                            headerName: t('auditEventSession'),
                            minWidth: 280,
                            valueGetter: (_value, row) => field(row, 'sessionId'),
                            renderCell: (params) =>
                                requestSensitive && rows?.source.sensitive ? (
                                    field(params.row, 'sessionId')
                                ) : (
                                    <span
                                        title={
                                            sourceInfo?.encrypted
                                                ? t('auditOverviewEncrypted')
                                                : undefined
                                        }
                                    >
                                        {t(
                                            sourceInfo?.encrypted
                                                ? 'auditPrivateEncrypted'
                                                : 'auditPrivateNotIncluded',
                                        )}
                                    </span>
                                ),
                        },
                    ]}
                    onPage={(index) => {
                        if (index <= page + 1 && cursors.current.at(index) !== undefined) {
                            setRows(null);
                            setPage(index);
                        }
                    }}
                    onQuery={(value) => {
                        cached.current = null;
                        setRows(null);
                        setPage(0);
                        setQuery(value);
                    }}
                    onSearch={(value, predicate) => {
                        cached.current = null;
                        setRows(null);
                        setPage(0);
                        setQuery(value);
                        setFilter(predicate);
                        const selected =
                            sessionScope && predicate?.field !== 'flow'
                                ? flow
                                : predicate?.field === 'flow' && predicate.operator === 'isEmpty'
                                  ? '-'
                                  : exactFlow(predicate);
                        const nextSession =
                            predicate?.field === 'sessionId'
                                ? predicate.operator === 'equals' && relationID(predicate.value)
                                    ? predicate.value
                                    : undefined
                                : predicate === null && filter?.field === 'sessionId'
                                  ? undefined
                                  : sessionScope;
                        if (
                            navigation &&
                            route &&
                            (selected !== flow || nextSession !== sessionScope)
                        ) {
                            native.current = { flow: selected, query: value, filter: predicate };
                            const {
                                flow: _flow,
                                id: _id,
                                eventHint: _event,
                                sessionId: _session,
                                ...parent
                            } = route;
                            navigation.navigate({
                                ...parent,
                                ...(selected ? { flow: selected } : {}),
                                ...(nextSession ? { sessionId: nextSession } : {}),
                            });
                        }
                    }}
                    onSort={(value) => {
                        cached.current = null;
                        setRows(null);
                        setPage(0);
                        setSort(value);
                    }}
                />
            </div>
            {target && detail && (
                <AuditEventDetails
                    id={detail.id}
                    recordedAt={detail.recordedAt}
                    event={detail.event}
                    sensitive={requestSensitive}
                    scope={view?.scope}
                    provenance={t('serverReported')}
                />
            )}
            {target && notFound === target && !detail && !failed && !busy && <ManagementNotFound />}
        </section>
    );
}
