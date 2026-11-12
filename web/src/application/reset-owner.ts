import type { WebAccess } from '../remember/client';
import type { ProfileResetPort, ProfileResetResult } from './reset-contracts';

export type ResetRequest =
    | { readonly kind: 'local' }
    | { readonly kind: 'peer'; readonly covered: readonly string[] };
export interface ResetBoundary {
    readonly accesses: readonly WebAccess[];
    closeViews(): boolean;
    readonly local: ProfileResetPort['local'];
    readonly peer: ProfileResetPort['peer'];
    begin(): {
        readonly interrupted: boolean;
        completed(result: ProfileResetResult): void;
        failed(error: unknown): void;
        finish(): void;
    };
}
const incomplete = (): ProfileResetResult => ({
    localCleared: false,
    remoteUnconfirmed: 1,
    viewsClosed: false,
});

// One application-local reset transaction. Peer and explicit local reset share
// serialization and receipt handling, but keep their different authorizations.
export class ApplicationResetOwner {
    #busy = false;
    get busy(): boolean {
        return this.#busy;
    }
    async run(request: ResetRequest, boundary: ResetBoundary): Promise<ProfileResetResult> {
        if (this.#busy) {
            return incomplete();
        }
        this.#busy = true;
        try {
            const publication = boundary.begin();
            try {
                const raw =
                    request.kind === 'peer'
                        ? await boundary.peer({
                              covered: request.covered,
                              accesses: boundary.accesses,
                              closeViews: boundary.closeViews,
                          })
                        : await boundary.local({
                              explicitConfirmation: true,
                              accesses: boundary.accesses,
                              closeViews: boundary.closeViews,
                          });
                const result = {
                    ...raw,
                    remoteUnconfirmed:
                        raw.remoteUnconfirmed +
                        (request.kind === 'peer' && publication.interrupted ? 1 : 0),
                };
                publication.completed(result);
                return result;
            } catch (error) {
                if (request.kind === 'peer') {
                    throw error;
                }
                publication.failed(error);
                return incomplete();
            } finally {
                publication.finish();
            }
        } finally {
            this.#busy = false;
        }
    }
}
