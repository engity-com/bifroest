export interface OperationLease {
    readonly signal: AbortSignal;
    current(): boolean;
    owned(): boolean;
    finish(): void;
}

// A local owner's single-flight slot. Cancellation never means that a remote
// mutation was undone; callers retain their own outcome/confirmation policy.
export class OperationSlot {
    #controller: AbortController | null = null;
    get busy(): boolean {
        return this.#controller !== null;
    }
    start(): OperationLease | null {
        if (this.#controller) {
            return null;
        }
        const controller = new AbortController();
        this.#controller = controller;
        return {
            signal: controller.signal,
            current: () => this.#controller === controller && !controller.signal.aborted,
            owned: () => this.#controller === controller,
            finish: () => {
                if (this.#controller === controller) {
                    this.#controller = null;
                }
            },
        };
    }
    cancel(): void {
        this.#controller?.abort();
    }
    retire(): void {
        const controller = this.#controller;
        this.#controller = null;
        controller?.abort();
    }
}
