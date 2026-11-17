import { RememberMeError } from '../remember/protocol';
import { resourceID, uuidClassic, uuidEqual } from '../shared/uuid';
import {
    actionPreparation,
    actionResult,
    type SessionAction,
    SessionActionConfirmation,
} from './action';
import {
    type AuditEventOptions,
    type AuditOverviewPage,
    auditEventFields,
    auditOverviewPage,
    type CatalogVerification,
    catalogVerification,
} from './audit-overview';
import type { ProgressListener, ReadProgress } from './progress';
import {
    type AuditlogSummary,
    auditlogName,
    detail,
    type FlowSummary,
    type Page,
    type PageOptions,
    page,
    pageFields,
    type RecordingOptions,
    type RecordingSummary,
    recordingFields,
    type SessionItem,
    type SessionOptions,
    sessionFields,
    type VersionInfo,
    versionInfo,
} from './protocol';

export interface ManagementPort {
    allowed(): void;
    closed(): boolean;
    post(
        action: string,
        fields: Record<string, string>,
        status: number,
        signal?: AbortSignal,
        progress?: ProgressListener,
    ): Promise<unknown>;
}
function completedPage<T>(
    value: Page<T>,
    total: number | undefined,
    after: string | undefined,
): Page<T> {
    if (total === undefined) {
        return value;
    }
    if (
        !Number.isSafeInteger(total) ||
        total < value.items.length ||
        (value.next !== '' && total <= value.items.length) ||
        (!after && value.next === '' && total !== value.items.length)
    ) {
        throw new RememberMeError('unavailable');
    }
    return Object.freeze({ ...value, total });
}

// Domain requests/response validation, bound to one grant by a private port.
// No token, browser storage, enrollment, channel admission or reconnect here.
export class ManagementClient {
    constructor(private readonly port: ManagementPort) {}
    async managementVersion(long = true, signal?: AbortSignal): Promise<VersionInfo> {
        this.port.allowed();
        if (typeof long !== 'boolean') {
            throw new RememberMeError('unavailable');
        }
        const result = versionInfo(
            await this.port.post('management/version/show', { long: String(long) }, 200, signal),
            long,
        );
        if (this.port.closed()) {
            throw new RememberMeError('denied');
        }
        return result;
    }
    async managementFlows(
        options: PageOptions = {},
        signal?: AbortSignal,
    ): Promise<Page<FlowSummary>> {
        this.port.allowed();
        const fields = pageFields(options);
        const result = page<FlowSummary>(
            await this.port.post('management/flows/list', fields, 200, signal),
            'flows',
            Number(fields.limit),
        );
        if (this.port.closed()) {
            throw new RememberMeError('denied');
        }
        return result;
    }
    async managementSessions(
        options: SessionOptions = {},
        signal?: AbortSignal,
    ): Promise<Page<SessionItem>> {
        this.port.allowed();
        const fields = sessionFields(options);
        const result = page<SessionItem>(
            await this.port.post('management/sessions/list', fields, 200, signal),
            'sessions',
            Number(fields.limit),
        );
        if (this.port.closed()) {
            throw new RememberMeError('denied');
        }
        return result;
    }
    #progress(progress?: ProgressListener) {
        let total: number | undefined;
        return {
            total: () => total,
            report: (value: ReadProgress) => {
                if (value.phase === 'finalizing' && value.total >= 0) {
                    total = value.total;
                }
                progress?.(value);
            },
        };
    }
    async managementAuditlogs(
        options: PageOptions = {},
        signal?: AbortSignal,
        progress?: ProgressListener,
    ): Promise<Page<AuditlogSummary>> {
        this.port.allowed();
        const fields = pageFields(options);
        const scan = this.#progress(progress);
        const result = page<AuditlogSummary>(
            await this.port.post('management/auditlogs/list', fields, 200, signal, scan.report),
            'auditlogs',
            Number(fields.limit),
        );
        if (this.port.closed()) {
            throw new RememberMeError('denied');
        }
        if (
            result.items.some(
                (row, index) =>
                    index > 0 &&
                    (fields.sort === 'name-desc'
                        ? row.name >= (result.items[index - 1]?.name ?? '')
                        : row.name <= (result.items[index - 1]?.name ?? '')),
            ) ||
            (result.next !== '' && (result.items.length === 0 || result.next === fields.after))
        ) {
            throw new RememberMeError('unavailable');
        }
        return completedPage(result, scan.total(), fields.after);
    }
    async managementRecordings(
        auditlog: string,
        options: RecordingOptions = {},
        signal?: AbortSignal,
        progress?: ProgressListener,
    ): Promise<Page<RecordingSummary>> {
        this.port.allowed();
        const scan = this.#progress(progress);
        const fields: Record<string, string> = {
            ...recordingFields(options),
            auditlog: auditlogName(auditlog),
        };
        const result = page<RecordingSummary>(
            await this.port.post('management/recordings/list', fields, 200, signal, scan.report),
            'recordings',
            Number(fields.limit),
        );
        if (this.port.closed()) {
            throw new RememberMeError('denied');
        }
        const startKey = (value: string) =>
            `${value.slice(0, 19)}.${value.slice(19, -1).replace('.', '').padEnd(9, '0')}`;
        if (
            new Set(result.items.map((row) => uuidClassic(row.id))).size !== result.items.length ||
            result.items.some((row, index) => {
                const previous = result.items[index - 1];
                const at = startKey(row.startedAt);
                return (
                    row.auditlog !== fields.auditlog ||
                    (fields.flow !== '' && row.flow !== fields.flow) ||
                    (fields.sessionId !== undefined &&
                        !uuidEqual(row.sessionId, fields.sessionId)) ||
                    (fields.user !== '' && row.user !== fields.user) ||
                    (fields.target !== '' && row.target !== fields.target) ||
                    (fields.status !== 'all' && row.status !== fields.status) ||
                    (fields.startedFrom !== '' && at < startKey(fields.startedFrom ?? '')) ||
                    (fields.startedUntil !== '' && at > startKey(fields.startedUntil ?? '')) ||
                    (previous !== undefined &&
                        ((fields.sort === 'started-asc'
                            ? at < startKey(previous.startedAt)
                            : at > startKey(previous.startedAt)) ||
                            (at === startKey(previous.startedAt) &&
                                uuidClassic(row.id) <= uuidClassic(previous.id))))
                );
            }) ||
            (result.next !== '' && (result.items.length === 0 || result.next === fields.after))
        ) {
            throw new RememberMeError('unavailable');
        }
        return completedPage(result, scan.total(), fields.after);
    }
    async managementAuditEvents(
        auditlog: string,
        options: AuditEventOptions = {},
        signal?: AbortSignal,
        progress?: ProgressListener,
    ): Promise<AuditOverviewPage> {
        this.port.allowed();
        const fields = auditEventFields(auditlog, options);
        const scan = this.#progress(progress);
        const result = auditOverviewPage(
            await this.port.post('management/audit-events/list', fields, 200, signal, scan.report),
            fields,
        );
        if (this.port.closed()) {
            throw new RememberMeError('denied');
        }
        return Object.freeze({
            ...completedPage(result, scan.total(), fields.after),
            source: result.source,
        });
    }
    async managementVerifyRecordings(
        auditlog: string,
        signal?: AbortSignal,
        progress?: ProgressListener,
    ): Promise<CatalogVerification> {
        this.port.allowed();
        const source = auditlogName(auditlog);
        const result = catalogVerification(
            await this.port.post(
                'management/recordings/verify',
                { auditlog: source },
                200,
                signal,
                progress,
            ),
            source,
        );
        if (this.port.closed()) {
            throw new RememberMeError('denied');
        }
        return result;
    }
    async managementSession(flow: string, id: string, signal?: AbortSignal): Promise<SessionItem> {
        this.port.allowed();
        if (
            typeof flow !== 'string' ||
            !flow.isWellFormed() ||
            new TextEncoder().encode(flow).length > 255 ||
            /[\p{Cc}]/u.test(flow) ||
            !resourceID(id)
        ) {
            throw new RememberMeError('unavailable');
        }
        const result = detail(
            await this.port.post('management/sessions/show', { flow, id }, 200, signal),
        );
        if (this.port.closed() || result.flow !== flow || !uuidEqual(result.id, id)) {
            throw new RememberMeError('denied');
        }
        return result;
    }
    async prepareSessionAction(
        action: SessionAction,
        flow: string,
        id: string,
        signal?: AbortSignal,
    ): Promise<SessionActionConfirmation> {
        this.port.allowed();
        if (
            !['disconnect', 'dispose'].includes(action) ||
            typeof flow !== 'string' ||
            !flow.isWellFormed() ||
            new TextEncoder().encode(flow).length > 255 ||
            /[\p{Cc}]/u.test(flow) ||
            !resourceID(id)
        ) {
            throw new RememberMeError('unavailable');
        }
        const prepared = actionPreparation(
            await this.port.post('management/sessions/prepare', { action, flow, id }, 202, signal),
            action,
            flow,
            id,
        );
        const handle = new SessionActionConfirmation(
            prepared.preview,
            async (stopped) => {
                this.port.allowed();
                const result = actionResult(
                    await this.port.post(
                        'management/sessions/confirm',
                        { confirmationToken: prepared.confirmationToken },
                        200,
                        stopped,
                    ),
                    prepared.preview,
                );
                if (this.port.closed()) {
                    throw new RememberMeError('denied');
                }
                return result;
            },
            async () => {
                this.port.allowed();
                await this.port.post(
                    'management/sessions/cancel',
                    { confirmationToken: prepared.confirmationToken },
                    204,
                );
            },
        );
        if (this.port.closed() || signal?.aborted) {
            await handle.cancel();
            throw new RememberMeError('cancelled');
        }
        return handle;
    }
}
