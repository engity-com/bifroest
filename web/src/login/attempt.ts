import type { BrowserClient, LoginStep, Scope, WebAccess } from '../remember';
import { RememberMeError } from '../remember/protocol';
import { OperationSlot } from '../shared/operation';
import { keyLoginError } from './diagnostic';
import { verificationLink } from './links';

export interface LoginSubmission {
    readonly method: 'password' | 'none' | 'keyboard-interactive' | 'public-key';
    readonly user: string;
    readonly password: string;
    readonly scope: Scope;
    privateFile: File | null;
    certificateFile: File | null;
    passphrase: string;
    readonly remember: boolean;
}
export interface LoginAttemptState {
    readonly phase:
        | 'idle'
        | 'authenticating'
        | 'enrolling'
        | 'authorized'
        | 'uncertain'
        | 'cancelled'
        | 'failed';
    readonly prompt: LoginStep | null;
    readonly provider: LoginStep | null;
}
export type LoginCompletion =
    | { readonly kind: 'mismatch'; readonly access: WebAccess }
    | {
          readonly kind: 'authorized';
          readonly access: WebAccess;
          readonly enrollment: 'none' | 'registered' | 'failed' | 'unknown';
          readonly error?: unknown;
      };

// One explicit authentication/enrollment attempt. Credentials and answers are
// never part of a snapshot. Routing, forms, saved usernames and views are ports.
export class LoginAttempt {
    #state: LoginAttemptState = { phase: 'idle', prompt: null, provider: null };
    #pending: { readonly step: LoginStep; answer(value: string): void } | null = null;
    readonly #slot = new OperationSlot();
    readonly #listeners = new Set<() => void>();
    readonly getSnapshot = () => this.#state;
    readonly subscribe = (listener: () => void) => {
        this.#listeners.add(listener);
        return () => {
            this.#listeners.delete(listener);
        };
    };
    #publish(state: LoginAttemptState): void {
        this.#state = Object.freeze(state);
        for (const listener of this.#listeners) {
            listener();
        }
    }
    clearProvider(): void {
        this.#publish({ ...this.#state, provider: null });
    }
    answer(step: LoginStep, value: string): void {
        if (this.#pending?.step === step) {
            this.#pending.answer(value);
        }
    }
    cancel(): boolean {
        const uncertain = this.#state.phase === 'enrolling' || this.#state.phase === 'uncertain';
        this.#slot.retire();
        this.#pending = null;
        this.#publish({
            phase: uncertain ? 'uncertain' : 'cancelled',
            prompt: null,
            provider: null,
        });
        return uncertain;
    }
    retire(): void {
        this.#slot.retire();
        this.#pending = null;
        this.#publish({ phase: 'idle', prompt: null, provider: null });
    }
    #prompt(step: LoginStep, signal: AbortSignal, current: () => boolean): Promise<string> {
        return new Promise((resolve, reject) => {
            const cleanup = () => {
                signal.removeEventListener('abort', aborted);
                if (this.#pending?.step === step) {
                    this.#pending = null;
                }
                if (current()) {
                    this.#publish({ ...this.#state, prompt: null });
                }
            };
            const aborted = () => {
                cleanup();
                reject(new RememberMeError('cancelled'));
            };
            if (signal.aborted) {
                aborted();
                return;
            }
            signal.addEventListener('abort', aborted, { once: true });
            this.#pending = {
                step,
                answer: (value) => {
                    if (!current() || signal.aborted || this.#pending?.step !== step) {
                        return;
                    }
                    cleanup();
                    resolve(value);
                },
            };
            this.#publish({
                ...this.#state,
                prompt: step,
                provider:
                    step.kind === 'info' && verificationLink(step.message) !== null ? step : null,
            });
        });
    }
    async start(
        client: Pick<BrowserClient, 'password' | 'interactive' | 'publicKey'>,
        request: LoginSubmission,
        ports: {
            readonly signal: AbortSignal;
            current(): boolean;
            admit(access: WebAccess): boolean;
        },
    ): Promise<LoginCompletion> {
        if (this.#state.phase === 'uncertain') {
            throw new RememberMeError('outcome-unknown');
        }
        const operation = this.#slot.start();
        if (!operation) {
            throw new RememberMeError('busy');
        }
        const signal = AbortSignal.any([ports.signal, operation.signal]);
        const current = () => operation.current() && !signal.aborted && ports.current();
        this.#publish({ phase: 'authenticating', prompt: null, provider: null });
        try {
            let access: WebAccess;
            if (request.method === 'public-key') {
                const file = request.privateFile;
                if (!file) {
                    throw new RememberMeError('key-import');
                }
                const key = await (async () => {
                    const { WasmLoginKey } = await import('./wasm-key').catch((error) => {
                        throw keyLoginError(error, 'module', 'unavailable');
                    });
                    return WasmLoginKey.import(
                        file,
                        request.passphrase,
                        request.certificateFile,
                        request.scope,
                        request.user,
                        signal,
                    );
                })()
                    .catch((error) => {
                        throw keyLoginError(error, 'key-import');
                    })
                    .finally(() => {
                        request.privateFile = null;
                        request.certificateFile = null;
                        request.passphrase = '';
                    });
                try {
                    access = await client.publicKey(request.user, key, signal);
                } catch (error) {
                    throw keyLoginError(error, 'authentication', 'unavailable');
                } finally {
                    key.close();
                }
            } else if (request.method === 'keyboard-interactive') {
                access = await client.interactive(
                    request.user,
                    (step, stopped) => this.#prompt(step, stopped, current),
                    signal,
                );
            } else {
                access = await client.password(
                    request.user,
                    request.method === 'none' ? '' : request.password,
                    signal,
                );
            }
            if (!current()) {
                throw new RememberMeError('cancelled');
            }
            if (!ports.admit(access)) {
                this.#publish({ phase: 'authorized', prompt: null, provider: null });
                return { kind: 'mismatch', access };
            }
            let enrollment: 'none' | 'registered' | 'failed' | 'unknown' = 'none';
            let failure: unknown;
            if (request.remember) {
                this.#publish({ phase: 'enrolling', prompt: null, provider: null });
                try {
                    await access.remember({ explicitOptIn: true }, signal);
                    enrollment = 'registered';
                } catch (error) {
                    failure = error;
                    enrollment =
                        error instanceof RememberMeError && error.code === 'outcome-unknown'
                            ? 'unknown'
                            : 'failed';
                }
            }
            if (!current()) {
                throw new RememberMeError('cancelled');
            }
            this.#publish({
                phase: enrollment === 'unknown' ? 'uncertain' : 'authorized',
                prompt: null,
                provider: null,
            });
            return {
                kind: 'authorized',
                access,
                enrollment,
                ...(failure === undefined ? {} : { error: failure }),
            };
        } catch (error) {
            if (current()) {
                this.#publish({ phase: 'failed', prompt: null, provider: null });
            }
            throw error;
        } finally {
            if (operation.current()) {
                this.#pending = null;
            }
            operation.finish();
        }
    }
}
