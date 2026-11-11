import type { LinkMetadata } from '../application/link-metadata';

export const savedLoginChoice = 'saved';

export function allowsSavedLogin(metadata: LinkMetadata): boolean {
    return metadata.loginOptions.some(
        (entry) => entry.rememberMe !== undefined && entry.rememberMe !== 'forbidden',
    );
}

export function loginChoiceFor(
    metadata: LinkMetadata,
    saved: boolean,
    selected: string | null,
): string {
    const first = metadata.loginOptions[0];
    const primary = first ? `${first.method}:${first.requestUser ? 'named' : 'nameless'}` : '';
    const available = saved && allowsSavedLogin(metadata);
    if (selected === savedLoginChoice && !available) {
        return primary;
    }
    return selected ?? (available ? savedLoginChoice : primary);
}
