// Cursor identity is opaque. A scope/filter change explicitly resets this
// inventory; no page lookup starts a request or infers a new cursor.
export class CursorPages {
    #values = [''];
    reset(): void {
        this.#values = [''];
    }
    at(index: number): string | undefined {
        return Number.isSafeInteger(index) && index >= 0 ? this.#values[index] : undefined;
    }
    completed(index: number, next: string): void {
        if (!Number.isSafeInteger(index) || index < 0 || this.#values[index] === undefined) {
            throw new Error('Unknown cursor page');
        }
        this.#values = [...this.#values.slice(0, index + 1), next];
    }
}
