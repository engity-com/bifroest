import { OperationSlot } from '../shared/operation';
import type { ActionPreview, SessionAction, SessionActionConfirmation } from './action';

export type SessionActionState =
    | { readonly phase: 'idle' | 'preparing' }
    | {
          readonly phase: 'ready' | 'sending' | 'confirmed' | 'unknown';
          readonly preview: ActionPreview;
      };

export interface SessionActionPort {
    prepareSessionAction(
        action: SessionAction,
        flow: string,
        id: string,
        signal: AbortSignal,
    ): Promise<SessionActionConfirmation>;
}
export interface SessionActionBoundary {
    canPrepare(): boolean;
    canConfirm(): boolean;
    lock(value: boolean): void;
    dispatched(): void;
    settled(): void;
    failed(error: unknown, mutation: boolean): void;
}

// Owns only a prepared mutation and its outcome. Read cursors, routes, React,
// dialogs and transport tokens cannot affect this state machine.
export class SessionActionOwner {
    #state: SessionActionState = { phase: 'idle' };
    #handle: SessionActionConfirmation | null = null;
    #mounted = false;
    readonly #operation = new OperationSlot();
    readonly #listeners = new Set<() => void>();
    constructor(
        private readonly port: SessionActionPort,
        private readonly boundary: () => SessionActionBoundary,
    ) {}
    readonly getSnapshot = () => this.#state;
    readonly subscribe = (listener: () => void) => {
        this.#listeners.add(listener);
        return () => {
            this.#listeners.delete(listener);
        };
    };
    #publish(state: SessionActionState): void {
        this.#state = Object.freeze(state);
        for (const listener of this.#listeners) {
            listener();
        }
    }
    mount(): () => void {
        this.#mounted = true;
        if (this.#state.phase === 'sending') {
            this.#publish({ phase: 'unknown', preview: this.#state.preview });
        }
        if (this.#state.phase === 'unknown') {
            this.boundary().lock(true);
        } else if (
            (this.#state.phase === 'preparing' || this.#state.phase === 'ready') &&
            !this.#handle
        ) {
            this.#publish({ phase: 'idle' });
        }
        return () => {
            this.#mounted = false;
            this.#operation.retire();
            void this.#handle?.cancel();
            this.#handle = null;
            this.boundary().lock(false);
        };
    }
    async prepare(
        action: SessionAction,
        target: { readonly flow: string; readonly id: string },
    ): Promise<void> {
        if (
            !this.#mounted ||
            !this.boundary().canPrepare() ||
            !['idle', 'confirmed'].includes(this.#state.phase)
        ) {
            return;
        }
        const operation = this.#operation.start();
        if (!operation) {
            return;
        }
        this.#publish({ phase: 'preparing' });
        try {
            const handle = await this.port.prepareSessionAction(
                action,
                target.flow,
                target.id,
                operation.signal,
            );
            if (!operation.current() || !this.#mounted || !this.boundary().canPrepare()) {
                await handle.cancel();
                return;
            }
            this.#handle = handle;
            this.#publish({ phase: 'ready', preview: handle.snapshot() });
        } catch (error) {
            if (operation.current()) {
                this.#publish({ phase: 'idle' });
                this.boundary().failed(error, false);
            }
        } finally {
            if (operation.current() && this.#state.phase === 'preparing') {
                this.#publish({ phase: 'idle' });
            }
            operation.finish();
        }
    }
    cancelPreparation(): void {
        if (this.#state.phase !== 'preparing' && this.#state.phase !== 'ready') {
            return;
        }
        this.#operation.retire();
        const handle = this.#handle;
        this.#handle = null;
        this.#publish({ phase: 'idle' });
        void handle?.cancel(); // Never an undo after dispatch.
    }
    async confirm(typed: string): Promise<void> {
        const state = this.#state;
        const handle = this.#handle;
        if (
            !this.#mounted ||
            !this.boundary().canConfirm() ||
            state.phase !== 'ready' ||
            !handle ||
            typed !== `${state.preview.target.flow}/${state.preview.target.id}`
        ) {
            return;
        }
        const operation = this.#operation.start();
        if (!operation) {
            return;
        }
        this.#handle = null;
        this.#publish({ phase: 'sending', preview: state.preview });
        this.boundary().dispatched();
        this.boundary().lock(true);
        try {
            await handle.confirm(operation.signal);
            if (operation.current()) {
                this.#publish({ phase: 'confirmed', preview: state.preview });
                this.boundary().lock(false);
            }
        } catch (error) {
            if (operation.current()) {
                this.#publish({ phase: 'unknown', preview: state.preview });
                this.boundary().failed(error, true);
            }
        } finally {
            if (operation.current()) {
                this.boundary().settled();
            }
            operation.finish();
        }
    }
    stopWaiting(): void {
        if (this.#state.phase !== 'sending') {
            return;
        }
        const preview = this.#state.preview;
        this.#operation.retire();
        this.#publish({ phase: 'unknown', preview });
        this.boundary().failed(undefined, true);
        this.boundary().settled();
        // Keep the owner locked until explicit dismissal, even if a late response
        // subsequently claims success. There is no replay or compensating request.
    }
    dismissUnknown(): void {
        if (this.#mounted && this.#state.phase === 'unknown') {
            this.#publish({ phase: 'idle' });
            this.boundary().lock(false);
        }
    }
}
