import { expect, it } from 'vitest';
import type { ManagementLocation } from '../src/application/management-location';
import { ViewIDs } from '../src/application/view-ids';

it('retains only live public view IDs and the one uncommitted activation', () => {
    const ids = new ViewIDs();
    for (let id = 1; id <= 100; id++) {
        ids.set(id, `public-${id}`);
        ids.reconcile([{ id, routeId: `public-${id}` }]);
        expect(ids.get(id - 1)).toBeUndefined();
    }
    ids.set(101, 'pending');
    ids.reconcile([{ id: 100 }], 101);
    expect(ids.get(101)).toBe('pending');
    ids.reconcile([{ id: 101, routeId: 'pending' }]);
    expect(ids.get(100)).toBeUndefined();
    ids.reconcile([]);
    expect(ids.get(101)).toBeUndefined();
});

// Compile-time contracts complement (never replace) runtime URL validation.
const valid: ManagementLocation = {
    managementFlow: 'admin',
    page: 'sessions',
    flow: 'exact',
    id: 'fixture',
};
// @ts-expect-error Overview cannot carry an evidence selector.
const invalidOverview: ManagementLocation = {
    managementFlow: 'admin',
    page: 'server',
    auditlog: 'private',
};
// @ts-expect-error A session detail requires its exact flow.
const missingFlow: ManagementLocation = {
    managementFlow: 'admin',
    page: 'sessions',
    id: 'fixture',
};
// @ts-expect-error Audit and recording source fields cannot be mixed.
const mixed: ManagementLocation = {
    managementFlow: 'admin',
    page: 'recordings',
    auditlog: 'private',
};
it('keeps type-only rejection fixtures out of application state', () => {
    expect(valid.page).toBe('sessions');
    expect([invalidOverview, missingFlow, mixed]).toHaveLength(3);
});
