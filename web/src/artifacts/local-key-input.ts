import { readLocalBytes } from '../wasm/local-file';
import { EvidenceError } from './evidence-protocol';
import type { EvidenceKey } from './verify';

// Read a one-shot local selection, not an authentication key or a server input.
export async function readEvidenceKey(
    file: Blob | undefined,
    passphrase: string,
    signal: AbortSignal,
): Promise<EvidenceKey | null> {
    if (!file) {
        return null;
    }
    if (file.size < 1 || file.size > 64 << 10) {
        throw new EvidenceError('key');
    }
    const bytes = await readLocalBytes(file, signal);
    try {
        return { file: new Blob([bytes]), passphrase };
    } finally {
        new Uint8Array(bytes).fill(0);
    }
}
