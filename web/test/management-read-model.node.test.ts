import { expect, it, vi } from 'vitest';
import type { Page, SessionItem } from '../src/management/protocol';
import {
    type ManagementReadBoundary,
    ManagementReadModel,
    type ManagementReadPort,
} from '../src/management/read-model';

const page: Page<SessionItem> = { items: [], next: 'cursor', skipped: 0 };
function fixture() {
    const pending = Promise.withResolvers<Page<SessionItem>>();
    const port: ManagementReadPort = {
        managementSessions: vi.fn(() => pending.promise),
        managementFlows: vi.fn(),
        managementSession: vi.fn(),
        managementVersion: vi.fn(),
    };
    const boundary: ManagementReadBoundary = {
        allowed: () => true,
        sessionsMatch: () => true,
        detailMatches: () => true,
        starting: vi.fn(),
        failed: vi.fn(),
    };
    const model = new ManagementReadModel(port, () => boundary);
    const unmount = model.mount();
    return { model, port, boundary, pending, unmount };
}
it('owns single-flight list receipts, filters and cursors independently of rendering', async () => {
    const f = fixture();
    const read = f.model.sessions({ flow: 'Exact', query: 'original', sort: 'flow-desc' }, 0);
    await f.model.flows({}, 0);
    expect(f.port.managementFlows).not.toHaveBeenCalled();
    f.pending.resolve(page);
    await read;
    expect(f.model.getSnapshot()).toMatchObject({
        loadedFlow: 'Exact',
        sessionQuery: 'original',
        sessionSort: 'desc',
        sessionPage: 1,
        completion: 1,
        loading: null,
    });
    expect(f.model.sessionCursor(1)).toBe('cursor');
    expect(f.model.lastFilter.flow).toBe('Exact');
    f.unmount();
});
it('cannot publish a late cancelled/old-owner response or let it finish a newer read', async () => {
    const f = fixture();
    const old = f.model.sessions({ flow: 'Old' }, 0);
    f.unmount();
    f.model.mount();
    const newer = Promise.withResolvers<Page<SessionItem>>();
    vi.mocked(f.port.managementSessions).mockReturnValueOnce(newer.promise);
    const current = f.model.sessions({ flow: 'New' }, 0);
    f.pending.resolve(page);
    await old;
    expect(f.model.getSnapshot().sessions).toBeNull();
    expect(f.model.busy).toBe(true);
    newer.resolve({ ...page, next: '' });
    await current;
    expect(f.model.getSnapshot().loadedFlow).toBe('New');
    expect(f.boundary.failed).not.toHaveBeenCalled();
});
it('checks the committed exact route after completion and does not retry failed reads', async () => {
    const f = fixture();
    const read = f.model.sessions({ flow: 'Exact' }, 0);
    f.boundary.sessionsMatch = () => false;
    f.pending.resolve(page);
    await read;
    expect(f.model.getSnapshot().sessions).toBeNull();
    expect(f.model.sessionCursor(1)).toBeUndefined();
    vi.mocked(f.port.managementSessions).mockRejectedValueOnce(
        new Error('private transport cause'),
    );
    await f.model.sessions({}, 0);
    expect(f.port.managementSessions).toHaveBeenCalledTimes(2);
    expect(f.boundary.failed).toHaveBeenCalledOnce();
    expect(JSON.stringify(f.model.getSnapshot())).not.toContain('private transport cause');
});
