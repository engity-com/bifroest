import type { ConnectionActions, TerminalActions } from '../terminal/connection-actions';

interface OwnedConnection {
    readonly cancellation: AbortController;
    terminal: TerminalActions | null;
    connection: ConnectionActions | null;
}

// Imperative capabilities have one owner and never become React state. IDs are
// not reused, so late cleanup cannot bind a new view to an old connection.
export class WorkspaceConnections {
    readonly #owned = new Map<number, OwnedConnection>();

    create(id: number): AbortSignal {
        if (this.#owned.has(id)) {
            throw new Error('Workspace connection ID already owned');
        }
        const cancellation = new AbortController();
        this.#owned.set(id, { cancellation, terminal: null, connection: null });
        return cancellation.signal;
    }

    active(id: number): boolean {
        return this.#owned.has(id);
    }

    terminal(id: number): TerminalActions | null {
        return this.#owned.get(id)?.terminal ?? null;
    }

    connection(id: number): ConnectionActions | null {
        return this.#owned.get(id)?.connection ?? null;
    }

    registerTerminal(id: number, actions: TerminalActions | null): void {
        const owned = this.#owned.get(id);
        if (owned) {
            owned.terminal = actions;
            owned.connection = actions;
        }
    }

    registerConnection(id: number, actions: ConnectionActions | null): void {
        const owned = this.#owned.get(id);
        if (owned) {
            owned.connection = actions;
        }
    }

    abort(id: number): void {
        const owned = this.#owned.get(id);
        this.#owned.delete(id);
        owned?.cancellation.abort();
    }

    abortAll(): void {
        for (const id of [...this.#owned.keys()]) {
            this.abort(id);
        }
    }
}
