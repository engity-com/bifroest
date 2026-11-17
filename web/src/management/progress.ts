// Provisional, count-only status. Never evidence, a result row or a completion
// receipt. -1 denotes an unknown total, not an empty inventory.
export interface ReadProgress {
    readonly phase: string;
    readonly completed: number;
    readonly total: number;
}
export type ProgressListener = (progress: ReadProgress) => void;
const phases = new Set([
    'waiting',
    'inventory',
    'verifying',
    'reverifying',
    'finalizing',
    'receiving',
    'validating',
    'reading',
    'integrity',
    'decrypting',
    'exporting',
    'indexing',
    'filtering',
    'metadata',
    'searching',
]);
export function readProgress(value: unknown): ReadProgress {
    if (
        value === null ||
        typeof value !== 'object' ||
        Array.isArray(value) ||
        Object.keys(value).sort().join(',') !== 'completed,phase,total'
    ) {
        throw new Error('invalid progress');
    }
    const item = value as ReadProgress;
    if (
        !phases.has(item.phase) ||
        !Number.isSafeInteger(item.completed) ||
        item.completed < 0 ||
        !Number.isSafeInteger(item.total) ||
        item.total < -1 ||
        (item.total >= 0 && item.completed > item.total)
    ) {
        throw new Error('invalid progress');
    }
    return Object.freeze({ ...item });
}
export function streamingManagementAction(action: string): boolean {
    return [
        'management/auditlogs/list',
        'management/recordings/list',
        'management/recordings/verify',
        'management/audit-events/list',
        'management/artifacts/audit',
        'management/artifacts/recording',
    ].includes(action);
}

export function remoteReadProgress(value: unknown): ReadProgress {
    const progress = readProgress(value);
    // A server may describe its own work, never claim that a local key,
    // decryption, signature check or audit index has been processed in the tab.
    if (
        ![
            'waiting',
            'inventory',
            'metadata',
            'searching',
            'verifying',
            'reverifying',
            'finalizing',
        ].includes(progress.phase)
    ) {
        throw new Error('invalid remote progress');
    }
    return progress;
}
