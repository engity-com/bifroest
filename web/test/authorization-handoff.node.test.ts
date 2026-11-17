import { expect, it } from 'vitest';
import { AuthorizationHandoff } from '../src/application/authorization-handoff';
import type { AccessSnapshot } from '../src/remember/client';

const grant = (flow = 'Exact') => ({
    snapshot: (): AccessSnapshot => ({
        scope: { origin: 'https://app.example.org', slug: 'Original' },
        principal: 'same-user',
        expiresAt: '2100-01-01T00:00:00Z',
        environment: 'management',
        terminalAvailable: false,
        flow: { name: flow, title: flow },
    }),
});
it('publishes a primary only after its enrollment outcome and acknowledges its exact owner', () => {
    const owner = new AuthorizationHandoff<ReturnType<typeof grant>>();
    const first = grant();
    const unrelated = grant();
    expect(owner.offer(first, 'Exact', true)).toBe(true);
    expect(owner.getSnapshot().phase).toBe('enrolling');
    expect(owner.event).toBeNull();
    expect(owner.acknowledge(first)).toBe(false);
    expect(owner.complete(unrelated, 'registered')).toBe(false);
    expect(owner.complete(first, 'registered')).toBe(true);
    expect(owner.acknowledge(unrelated)).toBe(false);
    expect(owner.candidate).toBe(first);
    expect(owner.acknowledge(first)).toBe(true);
    expect(owner.candidate).toBeNull();
    expect(owner.event).toBe(first);
    expect(owner.getSnapshot().phase).toBe('owned');
    expect(owner.complete(first, 'registered')).toBe(false);
});
it('cannot replay or dismiss an uncertain enrollment through tab selection or a second primary', () => {
    const owner = new AuthorizationHandoff<ReturnType<typeof grant>>();
    const first = grant();
    owner.offer(first, 'Exact', true);
    expect(owner.complete(first, 'unknown')).toBe(false);
    expect(owner.event).toBeNull();
    expect(owner.offer(grant(), 'Exact', false)).toBe(false);
    expect(owner.acknowledge(first)).toBe(false);
    expect(owner.complete(first, 'none')).toBe(false);
    expect(owner.candidate).toBe(first);
    owner.release(first);
    expect(owner.getSnapshot().phase).toBe('idle');
});
it('checks the exact management flow and keeps a mismatched grant available for explicit cleanup', () => {
    const owner = new AuthorizationHandoff<ReturnType<typeof grant>>();
    const first = grant();
    expect(owner.offer(first, 'exact', false)).toBe(false);
    expect(owner.candidate).toBe(first);
    expect(owner.getSnapshot().phase).toBe('mismatch');
    expect(owner.complete(first, 'none')).toBe(false);
    owner.clear();
    expect(owner.offer(first, '', false)).toBe(true);
    expect(owner.complete(first, 'none')).toBe(true);
    expect(JSON.stringify(owner.getSnapshot())).not.toContain('same-user');
});
