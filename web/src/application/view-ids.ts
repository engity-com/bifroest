// Volatile public route names, not credentials or a recoverable grant registry.
// A pending activation may precede its committed tab by one render.
export class ViewIDs {
    readonly #ids = new Map<number, string>();
    get(id: number): string | undefined {
        return this.#ids.get(id);
    }
    set(id: number, value: string): void {
        this.#ids.set(id, value);
    }
    reconcile(views: readonly { id: number; routeId?: string }[], pending?: number): void {
        const retained = new Set(views.map((view) => view.id));
        if (pending !== undefined) {
            retained.add(pending);
        }
        for (const id of this.#ids.keys()) {
            if (!retained.has(id)) {
                this.#ids.delete(id);
            }
        }
        for (const view of views) {
            if (view.routeId) {
                this.#ids.set(view.id, view.routeId);
            }
        }
    }
}
