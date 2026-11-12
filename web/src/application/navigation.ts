import { RememberMeError, type Scope } from '../remember/protocol';
import { OperationSlot } from '../shared/operation';
import { SnapshotObservers } from '../shared/snapshot-observers';
import type { ManagementLocation } from '../ui/management-location';
import type { ConnectionView } from '../workspace/model';
import type { LinkMetadata } from './link-metadata';

export interface ApplicationRouteIntent {
    readonly key: string;
    readonly revision: number;
    readonly canonicalizing: boolean;
    readonly scope: Scope | null;
    readonly view: number | null;
    readonly management: ManagementLocation | null;
}
export interface NavigationBoundary {
    readonly views: readonly ConnectionView[];
    readonly metadataScope: Scope;
    canonicalizing(): void;
    mismatch(): void;
    activate(view: ConnectionView, location: ManagementLocation | null): void;
    releaseStoppedAuthentication(): void;
    reuse(initial: boolean): void;
    invalidateDiscovery(): void;
    discover(scope: Scope | null): {
        current(): boolean;
        accepted(metadata: LinkMetadata): void;
        failed(error: unknown): void;
    };
}
export interface NavigationState {
    readonly phase: 'ready' | 'loading' | 'failed';
}

// Own only public discovery and route-intent consumption. Selecting an owned
// view never reads storage, authenticates, discovers metadata or starts a shell.
export class ApplicationNavigation {
    #state: NavigationState = { phase: 'ready' };
    #seen: { key: string; revision: number } | null = null;
    readonly #operation = new OperationSlot();
    readonly #observers = new SnapshotObservers();
    constructor(
        private readonly load: (scope: Scope, signal: AbortSignal) => Promise<LinkMetadata>,
    ) {}
    readonly getSnapshot = () => this.#state;
    readonly subscribe = this.#observers.subscribe;
    get busy(): boolean {
        return this.#operation.busy;
    }
    #publish(phase: NavigationState['phase']): void {
        if (this.#state.phase === phase) {
            return;
        }
        this.#state = Object.freeze({ phase });
        this.#observers.notify();
    }
    retire(): void {
        const pending = this.#operation.busy;
        this.#operation.retire();
        if (pending) {
            this.#publish('failed');
        }
    }
    reconcile(
        intent: ApplicationRouteIntent,
        boundary: NavigationBoundary,
    ): (() => void) | undefined {
        if (this.#seen?.key === intent.key && this.#seen.revision === intent.revision) {
            return;
        }
        if (intent.canonicalizing) {
            this.#operation.retire();
            this.#publish('ready');
            boundary.canonicalizing();
            return;
        }
        const initial = this.#seen === null;
        const retry = this.#seen !== null && this.#seen.revision !== intent.revision;
        this.#seen = { key: intent.key, revision: intent.revision };
        const selected = boundary.views.find(
            (view) =>
                view.id === intent.view &&
                view.scope.origin === intent.scope?.origin &&
                view.scope.slug === intent.scope?.slug,
        );
        if (selected) {
            const snapshot = selected.access.snapshot();
            if (
                intent.management &&
                (snapshot.environment !== 'management' ||
                    (intent.management.managementFlow !== '' &&
                        (snapshot.flow?.name ?? 'management') !== intent.management.managementFlow))
            ) {
                boundary.mismatch();
                return;
            }
            if (this.#operation.busy) {
                boundary.invalidateDiscovery();
            }
            this.#operation.retire();
            this.#publish('ready');
            boundary.activate(selected, intent.management);
            return;
        }
        boundary.releaseStoppedAuthentication();
        this.#operation.retire();
        if (
            !retry &&
            intent.scope?.origin === boundary.metadataScope.origin &&
            intent.scope.slug === boundary.metadataScope.slug
        ) {
            this.#publish('ready');
            boundary.reuse(initial);
            return;
        }
        const publication = boundary.discover(intent.scope);
        const scope = intent.scope;
        if (!scope) {
            this.#publish('failed');
            publication.failed(new RememberMeError('unavailable'));
            return;
        }
        const operation = this.#operation.start();
        if (!operation) {
            throw new Error('Discovery slot already owned');
        }
        this.#publish('loading');
        void Promise.resolve()
            .then(() => {
                if (!operation.current() || !publication.current()) {
                    throw new RememberMeError('cancelled');
                }
                return this.load(scope, operation.signal);
            })
            .then((metadata) => {
                if (operation.current() && publication.current()) {
                    publication.accepted(metadata);
                }
            })
            .catch((error) => {
                if (operation.current() && publication.current()) {
                    this.#publish('failed');
                    publication.failed(error);
                }
            })
            .finally(() => {
                if (operation.owned()) {
                    const loading = this.#state.phase === 'loading';
                    operation.finish();
                    if (loading) {
                        this.#publish('ready');
                    }
                }
            });
        return () => {
            if (operation.owned()) {
                this.#operation.cancel();
            }
        };
    }
}
