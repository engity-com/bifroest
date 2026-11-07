import { describe, expect, it } from 'vitest';
import { fixtureShellPromptPattern } from './shared-workload-prompt.mjs';

describe('owned shared-workload shell readiness', () => {
  const docker = new RegExp(fixtureShellPromptPattern('docker'));
  const kubernetes = new RegExp(fixtureShellPromptPattern('kubernetes'));
  const pod = 'bifroest-efbcee80-d508-11f1-868c-08bfb8192066';

  it('accepts the distinct observed Docker and Kubernetes fixture prompts', () => {
    expect(docker.test('~ $')).toBe(true);
    expect(kubernetes.test(`${pod}:/home/e2e$`)).toBe(true);
  });
  it('does not substitute one backend prompt for the other', () => {
    expect(docker.test(`${pod}:/home/e2e$`)).toBe(false);
    expect(kubernetes.test('~ $')).toBe(false);
  });
  it('does not accept missing, generic, root or different-directory prompts', () => {
    for (const text of ['', '$', '#', `${pod}:/root$`, `${pod}:/home/e2e#`, 'other:/home/e2e$']) {
      expect(docker.test(text)).toBe(false);
      expect(kubernetes.test(text)).toBe(false);
    }
  });
});
