import type { WebAccess } from '../remember/client';

export interface ProfileResetResult {
    readonly localCleared: boolean;
    readonly remoteUnconfirmed: number;
    readonly viewsClosed: boolean;
}
export interface ResetContext {
    readonly accesses: readonly WebAccess[];
    closeViews(): boolean;
}
export interface ProfileResetPort {
    local(
        options: ResetContext & { explicitConfirmation: boolean; signal?: AbortSignal },
    ): Promise<ProfileResetResult>;
    peer(options: ResetContext & { covered: readonly string[] }): Promise<ProfileResetResult>;
}
