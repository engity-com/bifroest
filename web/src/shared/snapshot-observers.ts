// Observers are notifications, never authority for an operation or its cleanup.
// Keep diagnostic data fixed: subscriber exceptions can contain private input.
export class SnapshotObservers {
    constructor(private readonly area: 'model-observer' | 'access-status' = 'model-observer') {}
    readonly #listeners = new Set<() => void>();
    readonly subscribe = (listener: () => void): (() => void) => {
        this.#listeners.add(listener);
        return () => {
            this.#listeners.delete(listener);
        };
    };
    notify(): void {
        for (const listener of [...this.#listeners]) {
            if (!this.#listeners.has(listener)) {
                continue;
            }
            try {
                listener();
            } catch {
                try {
                    console.error(`[Bifröst/${this.area}]`, 'listener-failed');
                } catch {
                    /* Diagnostics cannot become operation authority either. */
                }
            }
        }
    }
}
