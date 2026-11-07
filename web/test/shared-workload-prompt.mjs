// These are the two observed ash prompts of our pinned, owned fixtures, not a
// general terminal-readiness or authentication heuristic.
export function fixtureShellPromptPattern(backend) {
  if (backend === 'docker') {
    return '~ \\$$';
  }
  if (backend === 'kubernetes') {
    const uuid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
    return `^bifroest-${uuid}:/home/e2e\\$$`;
  }
  throw new Error('Unknown owned shell fixture backend');
}
