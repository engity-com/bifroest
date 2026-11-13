import type { RefObject } from 'react';

// Presentation bindings only. No key/passphrase value enters React state.
export interface LocalKeyInputFields {
    readonly input: RefObject<HTMLInputElement | null>;
    readonly form: RefObject<HTMLFormElement | null>;
    readonly id: string;
    readonly passwordID: string;
    readonly revision: number;
    readonly candidate: boolean;
    onCandidate(value: boolean): void;
}
export interface LocalKeySelection {
    readonly file: File | undefined;
    readonly passphrase: string;
}
export interface LocalKeyInput {
    readonly fields: LocalKeyInputFields;
    read(): LocalKeySelection;
    clear(): void;
    clearCandidate(): void;
}
