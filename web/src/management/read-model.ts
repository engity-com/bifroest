import { RememberMeError } from '../remember/protocol';
import { CursorPages } from '../shared/cursor-pages';
import { OperationSlot } from '../shared/operation';
import { SnapshotObservers } from '../shared/snapshot-observers';
import type {
    ColumnFilter,
    FlowSummary,
    Page,
    PageOptions,
    SessionItem,
    SessionOptions,
    VersionInfo,
} from './protocol';

export type ManagementReadResource = 'flows' | 'sessions' | 'details' | 'version' | 'build';
export interface ManagementReadPort {
    managementFlows(options: PageOptions, signal: AbortSignal): Promise<Page<FlowSummary>>;
    managementSessions(options: SessionOptions, signal: AbortSignal): Promise<Page<SessionItem>>;
    managementSession(flow: string, id: string, signal: AbortSignal): Promise<SessionItem>;
    managementVersion(long: boolean, signal: AbortSignal): Promise<VersionInfo>;
}
export interface ManagementReadBoundary {
    allowed(): boolean;
    sessionsMatch(options: SessionOptions): boolean;
    detailMatches(target: { flow: string; id: string }): boolean;
    starting(): void;
    failed(error: unknown, resource: ManagementReadResource): void;
}
export interface ManagementReadState {
    readonly flows: Page<FlowSummary> | null;
    readonly sessions: Page<SessionItem> | null;
    readonly selected: SessionItem | null;
    readonly version: VersionInfo | null;
    readonly buildVersion: VersionInfo | null;
    readonly loading: ManagementReadResource | null;
    readonly completion: number;
    readonly versionFailed: boolean;
    readonly sessionPage: number;
    readonly sessionQuery: string;
    readonly sessionSort: 'asc' | 'desc';
    readonly sessionFilter: ColumnFilter | null;
    readonly flowPage: number;
    readonly flowQuery: string;
    readonly flowSort: 'asc' | 'desc';
    readonly flowFilter: ColumnFilter | null;
    readonly loadedFlow: string | null;
}

// One access owner's read models and cursors. No mutation, navigation, DOM,
// implicit refresh or authentication capability enters this model.
export class ManagementReadModel {
    #state: ManagementReadState = {
        flows: null,
        sessions: null,
        selected: null,
        version: null,
        buildVersion: null,
        loading: null,
        completion: 0,
        versionFailed: false,
        sessionPage: 1,
        sessionQuery: '',
        sessionSort: 'asc',
        sessionFilter: null,
        flowPage: 1,
        flowQuery: '',
        flowSort: 'asc',
        flowFilter: null,
        loadedFlow: null,
    };
    #mounted = false;
    #epoch = 0;
    readonly #slot = new OperationSlot();
    readonly #sessions = new CursorPages();
    readonly #flows = new CursorPages();
    #lastFilter: SessionOptions = {};
    readonly #observers = new SnapshotObservers();
    readonly subscribe = this.#observers.subscribe;
    readonly getSnapshot = () => this.#state;
    get busy(): boolean {
        return this.#slot.busy;
    }
    get epoch(): number {
        return this.#epoch;
    }
    get lastFilter(): SessionOptions {
        return this.#lastFilter;
    }
    constructor(
        private readonly port: ManagementReadPort,
        private readonly boundary: () => ManagementReadBoundary,
    ) {}
    #publish(value: Partial<ManagementReadState>): void {
        this.#state = Object.freeze({ ...this.#state, ...value });
        this.#observers.notify();
    }
    mount(): () => void {
        this.#mounted = true;
        return () => {
            this.#mounted = false;
            this.cancel();
        };
    }
    cancel(): void {
        this.#epoch++;
        this.#slot.retire();
        this.#publish({ loading: null });
    }
    clearSessions(): void {
        this.#publish({ sessions: null, selected: null });
    }
    clearSelection(): void {
        this.#publish({ selected: null });
    }
    sessionIntent(filter: ColumnFilter | null, query: string): void {
        this.#sessions.reset();
        this.#publish({
            sessions: null,
            sessionPage: 1,
            sessionFilter: filter,
            sessionQuery: query,
        });
    }
    sessionFilter(filter: ColumnFilter | null, query = this.#state.sessionQuery): void {
        this.#publish({ sessionFilter: filter, sessionQuery: query });
    }
    rememberFilter(filter: SessionOptions): void {
        this.#lastFilter = Object.freeze({ ...filter });
    }
    invalidateSessions(filter: SessionOptions): void {
        this.rememberFilter(filter);
        this.#publish({ sessions: null, selected: null, loadedFlow: filter.flow ?? '' });
    }
    sessionCursor(index: number): string | undefined {
        return this.#sessions.at(index);
    }
    flowCursor(index: number): string | undefined {
        return this.#flows.at(index);
    }
    async #run(
        resource: ManagementReadResource,
        action: (signal: AbortSignal, current: () => boolean) => Promise<void>,
    ): Promise<void> {
        if (!this.#mounted || !this.boundary().allowed()) {
            return;
        }
        const operation = this.#slot.start();
        if (!operation) {
            return;
        }
        this.#epoch++;
        this.boundary().starting();
        this.#publish({ loading: resource });
        const current = () => this.#mounted && operation.current();
        try {
            await action(operation.signal, current);
        } catch (error) {
            if (current() && !(error instanceof RememberMeError && error.code === 'cancelled')) {
                if (resource === 'version') {
                    this.#publish({ versionFailed: true });
                }
                this.boundary().failed(error, resource);
            }
        } finally {
            if (operation.owned()) {
                operation.finish();
                this.#publish({ loading: null, completion: this.#state.completion + 1 });
            }
        }
    }
    async flows(options: PageOptions, index: number): Promise<void> {
        const selected = Object.freeze({ ...options });
        await this.#run('flows', async (signal, current) => {
            const result = await this.port.managementFlows(selected, signal);
            if (!current()) {
                return;
            }
            if (index === 0) {
                this.#flows.reset();
            }
            this.#flows.completed(index, result.next);
            this.#publish({
                flows: result,
                flowPage: index + 1,
                flowQuery: selected.query ?? '',
                flowFilter: selected.filter ?? null,
                flowSort: selected.sort === 'name-desc' ? 'desc' : 'asc',
            });
        });
    }
    async sessions(options: SessionOptions, index: number): Promise<void> {
        const selected = Object.freeze({ ...options });
        await this.#run('sessions', async (signal, current) => {
            const result = await this.port.managementSessions(selected, signal);
            if (!current() || !this.boundary().sessionsMatch(selected)) {
                return;
            }
            this.rememberFilter(selected);
            if (index === 0) {
                this.#sessions.reset();
            }
            this.#sessions.completed(index, result.next);
            this.#publish({
                sessions: result,
                selected: null,
                loadedFlow: selected.flow ?? '',
                sessionPage: index + 1,
                sessionQuery: selected.query ?? '',
                sessionFilter: selected.filter ?? null,
                sessionSort: selected.sort === 'flow-desc' ? 'desc' : 'asc',
            });
        });
    }
    async detail(target: { flow: string; id: string }): Promise<void> {
        const selected = Object.freeze({ ...target });
        await this.#run('details', async (signal, current) => {
            const result = await this.port.managementSession(selected.flow, selected.id, signal);
            if (current() && this.boundary().detailMatches(selected)) {
                this.#publish({ selected: result });
            }
        });
    }
    async version(long: boolean): Promise<void> {
        await this.#run(long ? 'build' : 'version', async (signal, current) => {
            const result = await this.port.managementVersion(long, signal);
            if (current()) {
                this.#publish(
                    long ? { buildVersion: result } : { version: result, versionFailed: false },
                );
            }
        });
    }
}
