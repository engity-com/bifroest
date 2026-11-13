import type { Scope } from '../remember/protocol';

export type LoginMethod = 'password' | 'keyboard-interactive' | 'public-key' | 'none';
export interface LoginOption {
    readonly method: LoginMethod;
    readonly requestUser: boolean;
    readonly certificateRequired: boolean;
}
export interface LinkMetadata {
    readonly scope: Scope;
    readonly loginOptions: readonly LoginOption[];
    readonly publishedSlugs: readonly string[];
    readonly rootAvailable: boolean;
}
