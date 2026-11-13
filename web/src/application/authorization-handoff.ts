import type { AccessSnapshot } from '../remember/client';
import { SnapshotObservers } from '../shared/snapshot-observers';

export interface AuthorizationGrant {
    snapshot(): AccessSnapshot;
}
export interface AuthorizationHandoffState {
    readonly phase:
        | 'idle'
        | 'primary-confirmed'
        | 'enrolling'
        | 'ready'
        | 'owned'
        | 'mismatch'
        | 'uncertain';
    readonly revision: number;
}

// One application's explicit primary/enrollment/workspace handoff. Grant handles
// stay private; snapshots contain only lifecycle metadata, never bearer material.
export class AuthorizationHandoff<T extends AuthorizationGrant> {
    #candidate: T | null = null;
    #event: T | null = null;
    #state: AuthorizationHandoffState = { phase: 'idle', revision: 0 };
    readonly #observers = new SnapshotObservers();
    readonly subscribe = this.#observers.subscribe;
    readonly getSnapshot = () => this.#state;
    get candidate(): T | null {
        return this.#candidate;
    }
    get event(): T | null {
        return this.#event;
    }
    #publish(phase: AuthorizationHandoffState['phase']): void {
        this.#state = Object.freeze({ phase, revision: this.#state.revision + 1 });
        this.#observers.notify();
    }
    offer(grant: T, expectedFlow: string | null, enrolling: boolean): boolean {
        if (this.#state.phase === 'uncertain') {
            return false;
        }
        this.#candidate = grant;
        const snapshot = grant.snapshot();
        const matches =
            expectedFlow === null ||
            (snapshot.environment === 'management' &&
                (expectedFlow === '' || snapshot.flow?.name === expectedFlow));
        this.#publish(!matches ? 'mismatch' : enrolling ? 'enrolling' : 'primary-confirmed');
        return matches;
    }
    complete(grant: T, enrollment: 'none' | 'registered' | 'failed' | 'unknown'): boolean {
        if (
            grant !== this.#candidate ||
            !['primary-confirmed', 'enrolling'].includes(this.#state.phase)
        ) {
            return false;
        }
        if (enrollment === 'unknown') {
            this.#publish('uncertain');
            return false;
        }
        this.#event = grant;
        this.#publish('ready');
        return true;
    }
    uncertain(): void {
        this.#publish('uncertain');
    }
    acknowledge(grant: T | null): boolean {
        if (this.#state.phase === 'uncertain' || this.#state.phase === 'enrolling') {
            return false;
        }
        if (this.#candidate !== null && this.#candidate !== grant) {
            return false;
        }
        if (grant !== null && this.#candidate === grant) {
            this.#candidate = null;
            this.#publish('owned');
        }
        return true;
    }
    release(grant: T): void {
        if (this.#candidate === grant) {
            this.#candidate = null;
        }
        if (this.#event === grant) {
            this.#event = null;
        }
        if (this.#candidate === null) {
            this.#publish('idle');
        }
    }
    clear(): void {
        this.#candidate = null;
        this.#event = null;
        this.#publish('idle');
    }
}
