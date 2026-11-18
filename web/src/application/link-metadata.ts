import type { RememberMePolicy } from '../remember/policy';
import type { Scope } from '../remember/protocol';
import { RememberMeError } from '../remember/protocol';

export type DiscoveryFailure = 'invalid-slug' | 'unavailable';
export function discoveryFailure(error: unknown): DiscoveryFailure {
    return error instanceof RememberMeError && error.code === 'not-found'
        ? 'invalid-slug'
        : 'unavailable';
}

export type LoginMethod = 'password' | 'keyboard-interactive' | 'oidc' | 'public-key' | 'none';
export interface LoginOption {
    readonly method: LoginMethod;
    readonly requestUser: boolean;
    readonly certificateRequired: boolean;
    readonly rememberMe?: RememberMePolicy;
}
export interface LinkMetadata {
    readonly scope: Scope;
    readonly loginOptions: readonly LoginOption[];
    readonly publishedSlugs: readonly string[];
    readonly rootAvailable: boolean;
}
