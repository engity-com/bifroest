import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReadProgress as Progress } from '../management/progress';
import type { ColumnFilter } from '../management/protocol';
import { uuidEqual, uuidInputPattern } from '../shared/uuid';
import { AdminBreadcrumbs } from '../ui/AdminBreadcrumbs';
import { AdminDataGrid } from '../ui/AdminDataGrid';
import { relationID } from '../ui/ManagementJump';
import { ManagementNotFound } from '../ui/ManagementNotFound';
import { exactFlow, type ManagementLocation } from '../ui/management-location';
import { useManagementNavigation } from '../ui/management-navigation';
import { Alert, Button, TextInput } from '../ui/material';
import { t } from '../ui/messages';
import { AuditEventActions, AuditEventDetails } from './AuditEventDetails';
import { useAuditView } from './AuditViewContext';
import {
    type AuditEventIndex,
    type AuditEventRow,
    auditEventByID,
    auditEventPage,
    indexAuditEvents,
} from './audit-events';

export function AuditEvents({
    source,
    active,
    selected: controlled,
    onSelect,
    privateFieldsKnown = false,
    initialIndex,
}: {
    source: Blob;
    active: boolean;
    selected?: AuditEventRow | null;
    onSelect?: (row: AuditEventRow | null) => void;
    privateFieldsKnown?: boolean;
    initialIndex?: AuditEventIndex | undefined;
}) {
    const view = useAuditView();
    const retainSelection = view !== null;
    const navigation = useManagementNavigation();
    const route = navigation?.location.page === 'auditlogs' ? navigation.location : null;
    const routeKey = JSON.stringify(route);
    const navigateRef = useRef(navigation);
    navigateRef.current = navigation;
    const returnRoute = useRef<ManagementLocation | null>(null);
    const cachedEvent = useRef<{ source: Blob; key: string; row: AuditEventRow } | null>(null);
    const [eventInput, setEventInput] = useState('');
    const nativeFilterIntent = useRef<{
        flow: string | undefined;
        query: string;
        filter: ColumnFilter | null;
    } | null>(null);
    const [rows, setRows] = useState<AuditEventRow[]>([]);
    const [page, setPage] = useState(0);
    const [query, setQuery] = useState('');
    const [filter, setFilter] = useState<ColumnFilter | null>(null);
    const [sort, setSort] = useState<'asc' | 'desc'>('desc');
    const [next, setNext] = useState(false);
    const [total, setTotal] = useState<number | undefined>(undefined);
    const [busy, setBusy] = useState(false);
    const [progress, setProgress] = useState<Progress | null>(null);
    const [cancelled, setCancelled] = useState(false);
    const operation = useRef<AbortController | null>(null);
    const [failed, setFailed] = useState(false);
    const [notFound, setNotFound] = useState<string | null>(null);
    const [ownSelected, setOwnSelected] = useState<AuditEventRow | null>(null);
    const [refresh, setRefresh] = useState(0);
    const rawSelected = controlled === undefined ? ownSelected : controlled;
    const requestedID = route?.id ?? route?.eventHint;
    const detailIntent = !!requestedID;
    const selected =
        navigation && route
            ? rawSelected &&
              uuidEqual(rawSelected.record.id, requestedID) &&
              (!route.flow ||
                  (route.flow === '-' ? rawSelected.flow === '' : rawSelected.flow === route.flow))
                ? rawSelected
                : null
            : rawSelected;
    const shownFilter: ColumnFilter | null =
        route && !detailIntent
            ? route.sessionId
                ? { field: 'sessionId', operator: 'equals', value: route.sessionId }
                : route.flow
                  ? {
                        field: 'flow',
                        operator: route.flow === '-' ? 'isEmpty' : 'equals',
                        value: route.flow === '-' ? '' : route.flow,
                    }
                  : exactFlow(filter) || (filter?.field === 'flow' && filter.operator === 'isEmpty')
                    ? null
                    : filter
            : filter;
    const choose = useCallback(
        (row: AuditEventRow | null) => {
            setOwnSelected(row);
            onSelect?.(row);
        },
        [onSelect],
    );
    const detailed = privateFieldsKnown;
    const index = useRef<AuditEventIndex | null>(initialIndex ?? null);
    const generation = useRef(0);
    const indexedRevision = useRef(0);
    const listScope = useRef<string | undefined>(undefined);
    useEffect(() => {
        if (index.current?.source === source) {
            return;
        }
        index.current = initialIndex?.source === source ? initialIndex : null;
        if (index.current) {
            indexedRevision.current = refresh;
        }
        cachedEvent.current = null;
        returnRoute.current = null;
        setRows([]);
        if (!retainSelection) {
            listScope.current = undefined;
            setPage(0);
            setQuery('');
            setFilter(null);
        }
        choose(null);
    }, [source, choose, initialIndex, refresh, retainSelection]);
    useEffect(() => {
        const controller = new AbortController();
        const current = ++generation.current;
        if (!active) {
            return;
        }
        operation.current = controller;
        setBusy(true);
        setTotal(undefined);
        setRows([]);
        setProgress(null);
        setCancelled(false);
        setFailed(false);
        void (async () => {
            const report = (value: Progress) => {
                if (current === generation.current && !controller.signal.aborted) {
                    setProgress(value);
                }
            };
            try {
                const ownedIndex =
                    index.current?.source === source && indexedRevision.current === refresh
                        ? index.current
                        : await indexAuditEvents(source, controller.signal, report);
                if (current !== generation.current || controller.signal.aborted) {
                    return;
                }
                index.current = ownedIndex;
                indexedRevision.current = refresh;
                const target = JSON.parse(routeKey) as ManagementLocation | null;
                if (target && (target.id || target.eventHint)) {
                    const id = target.id ?? target.eventHint ?? '';
                    const key = JSON.stringify([
                        target.auditlog,
                        target.flow,
                        target.id,
                        target.eventHint,
                        target.sessionId,
                    ]);
                    const cached = cachedEvent.current;
                    if (cached?.source === source && cached.key === key) {
                        choose(cached.row);
                        return;
                    }
                    choose(null);
                    const row = await auditEventByID(
                        ownedIndex,
                        id,
                        controller.signal,
                        target.flow,
                        report,
                        target.sessionId,
                        privateFieldsKnown,
                    );
                    if (current !== generation.current || controller.signal.aborted) {
                        return;
                    }
                    if (!row || !target.auditlog) {
                        setNotFound(routeKey);
                        return;
                    }
                    const canonical: ManagementLocation = {
                        managementFlow: target.managementFlow,
                        page: 'auditlogs',
                        auditlog: target.auditlog,
                        id,
                        ...(target.flow ? { flow: target.flow } : {}),
                        ...(target.sessionId ? { sessionId: target.sessionId } : {}),
                    };
                    cachedEvent.current = {
                        source,
                        key: JSON.stringify([
                            canonical.auditlog,
                            canonical.flow,
                            canonical.id,
                            canonical.eventHint,
                            canonical.sessionId,
                        ]),
                        row,
                    };
                    choose(row);
                    if (target.eventHint && canonical.id) {
                        navigateRef.current?.navigate(canonical, true);
                    }
                    return;
                }
                if (navigateRef.current) {
                    choose(null);
                }
                const requestedFilter: ColumnFilter | null = target?.sessionId
                    ? { field: 'sessionId', operator: 'equals', value: target.sessionId }
                    : target?.flow
                      ? {
                            field: 'flow',
                            operator: target.flow === '-' ? 'isEmpty' : 'equals',
                            value: target.flow === '-' ? '' : target.flow,
                        }
                      : target &&
                          (exactFlow(filter) ||
                              (filter?.field === 'flow' && filter.operator === 'isEmpty'))
                        ? null
                        : filter;
                const scopeKey = JSON.stringify([target?.flow, target?.sessionId]);
                const scopeChanged = scopeKey !== listScope.current;
                const native =
                    nativeFilterIntent.current?.flow === target?.flow
                        ? nativeFilterIntent.current
                        : null;
                const result = await auditEventPage(
                    ownedIndex,
                    scopeChanged ? 0 : page,
                    scopeChanged ? (native?.query ?? '') : query,
                    requestedFilter,
                    sort === 'desc',
                    controller.signal,
                    target?.flow,
                    report,
                    target?.sessionId,
                    privateFieldsKnown,
                );
                if (current === generation.current && !controller.signal.aborted) {
                    listScope.current = scopeKey;
                    if (scopeChanged) {
                        setPage(0);
                        setQuery(native?.query ?? '');
                    }
                    nativeFilterIntent.current = null;
                    setRows(result.items);
                    setNext(result.next !== '');
                    setTotal(result.total);
                }
            } catch {
                if (current === generation.current && controller.signal.aborted) {
                    setCancelled(true);
                    setRows([]);
                }
                if (current === generation.current && !controller.signal.aborted) {
                    setRows([]);
                    setFailed(true);
                }
            } finally {
                if (current === generation.current) {
                    if (controller.signal.aborted) {
                        setCancelled(true);
                        setRows([]);
                    }
                    setBusy(false);
                    if (operation.current === controller) {
                        operation.current = null;
                    }
                }
            }
        })();
        return () => controller.abort();
    }, [source, active, page, query, filter, sort, refresh, routeKey, choose, privateFieldsKnown]);
    function openRow(row: AuditEventRow) {
        if (navigation && route?.auditlog && typeof row.record.id === 'string') {
            returnRoute.current = route;
            navigation.navigate({
                managementFlow: route.managementFlow,
                page: 'auditlogs',
                auditlog: route.auditlog,
                id: row.record.id,
                ...(route.flow ? { flow: route.flow } : {}),
                ...(route.sessionId ? { sessionId: route.sessionId } : {}),
            });
        } else {
            choose(row);
        }
    }
    function close() {
        if (navigation && route) {
            const { id: _id, eventHint: _hint, ...parent } = route;
            navigation.navigate(returnRoute.current ?? parent);
        } else {
            choose(null);
        }
    }
    const event = selected?.record.event;
    const fields =
        event !== null && typeof event === 'object' && !Array.isArray(event)
            ? (event as Record<string, unknown>)
            : {};
    return (
        <section className="stack" aria-label={t('auditEvents')}>
            {cancelled && <Alert>{t('artifactCatalogCancelled')}</Alert>}
            {failed && <Alert color="red">{t('auditEventsFailed')}</Alert>}
            {busy && detailIntent && selected === null && (
                <p role="status">{t('auditEventLoading')}</p>
            )}
            {detailIntent && notFound === routeKey && !busy && !selected && !failed && (
                <ManagementNotFound />
            )}
            <div hidden={selected !== null || detailIntent}>
                <AdminDataGrid<AuditEventRow>
                    active={active && selected === null && !detailIntent}
                    label={t('auditEvents')}
                    resultAvailable={
                        !busy && !failed && !cancelled && index.current?.source === source
                    }
                    rows={
                        !route ||
                        listScope.current === JSON.stringify([route.flow, route.sessionId])
                            ? rows
                            : []
                    }
                    readProgress={progress}
                    onCancelRead={() => operation.current?.abort()}
                    detailToggle={
                        view
                            ? {
                                  checked: view.sensitive,
                                  onChange: view.toggleSensitive,
                                  disabled: view.running,
                                  label: 'privateDetails',
                              }
                            : undefined
                    }
                    rowActions={(row) => (
                        <AuditEventActions
                            event={row.record.event as Record<string, unknown>}
                            scope={view?.scope}
                            sensitive={privateFieldsKnown}
                            compact
                            disabled={busy || !active}
                        />
                    )}
                    onOpen={openRow}
                    openByID={
                        <form
                            method="dialog"
                            className="actions"
                            onSubmit={(event) => {
                                event.preventDefault();
                                if (navigation && route?.auditlog) {
                                    returnRoute.current = route;
                                    navigation.navigate({
                                        managementFlow: route.managementFlow,
                                        page: 'auditlogs',
                                        auditlog: route.auditlog,
                                        eventHint: eventInput,
                                    });
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
                            <Button type="submit" disabled={busy || !active || !navigation}>
                                Go
                            </Button>
                        </form>
                    }
                    openLabel={(row) => `${t('auditEventDetails')} ${row.id}`}
                    detailsAvailable
                    detailed={detailed}
                    detailFields={['reason', 'sessionId']}
                    onRefresh={() => setRefresh((value) => value + 1)}
                    refreshLabel={t('auditRefreshEvents')}
                    columns={[
                        {
                            field: 'recordedAt',
                            headerName: t('auditRecordedAt'),
                            type: 'dateTime',
                            minWidth: 190,
                            valueFormatter: (value) =>
                                new Intl.DateTimeFormat(undefined, {
                                    dateStyle: 'medium',
                                    timeStyle: 'medium',
                                }).format(value as Date),
                        },
                        { field: 'name', headerName: t('auditEventName'), minWidth: 260, flex: 1 },
                        { field: 'outcome', headerName: t('auditEventOutcome'), minWidth: 120 },
                        {
                            field: 'flow',
                            headerName: t('recordingFilterFlow'),
                            minWidth: 130,
                            renderCell: (params) =>
                                privateFieldsKnown ? params.row.flow : t('auditPrivateNotIncluded'),
                        },
                        {
                            field: 'reason',
                            headerName: t('auditEventReason'),
                            minWidth: 180,
                            valueGetter: (_value, row) => (privateFieldsKnown ? row.reason : ''),
                            renderCell: (params) =>
                                privateFieldsKnown
                                    ? params.row.reason
                                    : t('auditPrivateNotIncluded'),
                        },
                        {
                            field: 'sessionId',
                            headerName: t('auditEventSession'),
                            minWidth: 280,
                            valueGetter: (_value, row) => (privateFieldsKnown ? row.sessionId : ''),
                            renderCell: (params) =>
                                privateFieldsKnown
                                    ? params.row.sessionId
                                    : t('auditPrivateNotIncluded'),
                        },
                    ]}
                    busy={busy}
                    disabled={!active}
                    page={page}
                    hasNext={next}
                    total={total}
                    query={query}
                    columnFilter={shownFilter}
                    sortField="recordedAt"
                    sortDirection={sort}
                    onPage={setPage}
                    onQuery={(value) => {
                        setQuery(value);
                        setPage(0);
                    }}
                    onSearch={(query, filter) => {
                        setQuery(query);
                        setFilter(filter);
                        setPage(0);
                        const flow =
                            route?.sessionId && filter?.field !== 'flow'
                                ? route.flow
                                : filter?.field === 'flow' && filter.operator === 'isEmpty'
                                  ? '-'
                                  : exactFlow(filter);
                        const nextSession =
                            filter?.field === 'sessionId'
                                ? filter.operator === 'equals' && relationID(filter.value)
                                    ? filter.value
                                    : undefined
                                : route?.sessionId;
                        if (
                            navigation &&
                            route &&
                            (flow !== route.flow || nextSession !== route.sessionId)
                        ) {
                            nativeFilterIntent.current = { flow, query, filter };
                            const {
                                flow: _flow,
                                id: _id,
                                eventHint: _hint,
                                sessionId: _session,
                                ...parent
                            } = route;
                            navigation.navigate({
                                ...parent,
                                ...(flow ? { flow } : {}),
                                ...(nextSession ? { sessionId: nextSession } : {}),
                            });
                        }
                    }}
                    onSort={(value) => {
                        setSort(value);
                        setPage(0);
                    }}
                />
            </div>
            {selected && (
                <>
                    {!navigation && (
                        <AdminBreadcrumbs
                            items={[
                                { label: t('auditEvents'), onClick: close },
                                { label: String(selected.record.id ?? selected.id) },
                            ]}
                        />
                    )}
                    <AuditEventDetails
                        id={String(selected.record.id ?? selected.id)}
                        recordedAt={selected.recordedAt}
                        event={fields}
                        envelope={selected.record}
                        scope={view?.scope}
                        sensitive={privateFieldsKnown}
                        provenance={view?.provenance ?? t('locallyChecked')}
                    />
                </>
            )}
        </section>
    );
}
