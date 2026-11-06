import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { expect, it, vi } from 'vitest';
import { AuditEvents } from '../src/artifacts/AuditEvents';
import {
  type AuditEventIndex,
  auditEventPage,
  indexAuditEvents,
} from '../src/artifacts/audit-events';
import '../src/ui/app.css';

vi.mock('../src/artifacts/audit-events', () => ({
  indexAuditEvents: vi.fn(),
  auditEventPage: vi.fn(),
  auditEventByID: vi.fn(),
}));
const indexFor = (source: Blob): AuditEventIndex => ({
  source,
  offsets: new Uint32Array(1),
  lengths: new Uint32Array(1),
  times: new Float64Array(1),
  count: 1,
});
it('does not let a late old-source index poison a reactivated new-source view', async () => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  const old = new Blob(['old']);
  const current = new Blob(['current']);
  const oldIndex = Promise.withResolvers<AuditEventIndex>();
  const firstCurrent = Promise.withResolvers<AuditEventIndex>();
  const resumedCurrent = Promise.withResolvers<AuditEventIndex>();
  let attempts = 0;
  vi.mocked(indexAuditEvents).mockImplementation(async (source) =>
    source === old
      ? oldIndex.promise
      : ++attempts === 1
        ? firstCurrent.promise
        : resumedCurrent.promise,
  );
  vi.mocked(auditEventPage).mockImplementation(async (index) => ({
    items: [
      {
        id: '1',
        recordedAt: new Date('2026-11-04T12:00:00Z'),
        name: index.source === old ? 'OLD-ARTIFACT' : 'CURRENT-ARTIFACT',
        outcome: 'success',
        flow: 'work',
        reason: '',
        sessionId: '',
        record: {},
      },
    ],
    next: '',
    skipped: 0,
  }));
  const host = document.createElement('div');
  host.style.width = '1200px';
  document.body.append(host);
  const root = createRoot(host);
  const render = async (source: Blob, active = true) =>
    act(async () => root.render(createElement(AuditEvents, { source, active })));
  try {
    await render(old);
    await render(current);
    await act(async () => oldIndex.resolve(indexFor(old)));
    await render(current, false);
    await render(current, true);
    await vi.waitFor(() => expect(indexAuditEvents).toHaveBeenCalledTimes(3));
    expect(auditEventPage).not.toHaveBeenCalled();
    await act(async () => resumedCurrent.resolve(indexFor(current)));
    await vi.waitFor(() => expect(host.textContent).toContain('CURRENT-ARTIFACT'));
    await act(async () => firstCurrent.resolve(indexFor(current)));
    expect(host.textContent).not.toContain('OLD-ARTIFACT');
    expect(auditEventPage).toHaveBeenCalledTimes(1);
    expect(vi.mocked(auditEventPage).mock.calls[0]?.[0].source).toBe(current);
  } finally {
    await act(async () => root.unmount());
    host.remove();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  }
});
