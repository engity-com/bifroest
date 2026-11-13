// These are the two observed ash prompts of our pinned, owned fixtures, not a
// general terminal-readiness or authentication heuristic.
export function fixtureShellPromptPattern(backend) {
    if (backend === 'docker') {
        return '~ \\$$';
    }
    if (backend === 'kubernetes') {
        const nameHash = '[0-9a-f]{32}';
        return `^bifroest-${nameHash}:/home/e2e\\$$`;
    }
    throw new Error('Unknown owned shell fixture backend');
}
