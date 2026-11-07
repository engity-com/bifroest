import { expect, it, vi } from 'vitest';
import { auditEventByID, auditEventPage, indexAuditEvents } from '../src/artifacts/audit-events';

function record(index: number) {
  return {
    id: `event-${index}`,
    recordedAt: new Date(Date.UTC(2026, 10, 4, 0, index)).toISOString(),
    event: {
      name: index % 2 ? 'session.task.completed' : 'authentication.completed',
      outcome: index % 3 ? 'success' : 'denied',
      flow: 'work',
      sessionId: `session-${index}`,
    },
  };
}
it('streams local indexing/filter progress without relying on visible animation frames and cancels between bounded sections', async () => {
  const source = new Blob(
    Array.from({ length: 5000 }, (_, index) => `${JSON.stringify(record(index))}\n`),
  );
  const animation = vi.spyOn(globalThis, 'requestAnimationFrame').mockImplementation(() => {
    throw new Error('indexing must not wait for a visible animation frame');
  });
  try {
    const progress = vi.fn();
    const index = await indexAuditEvents(source, new AbortController().signal, progress);
    expect(progress).toHaveBeenCalledWith({ phase: 'indexing', completed: 4096, total: -1 });
    expect(progress).toHaveBeenLastCalledWith({ phase: 'indexing', completed: 5000, total: 5000 });
    expect(index.count).toBe(5000);
    const filterProgress = vi.fn();
    const page = await auditEventPage(
      index,
      0,
      'work',
      null,
      true,
      new AbortController().signal,
      undefined,
      filterProgress,
    );
    expect(page.items).toHaveLength(20);
    expect(filterProgress).toHaveBeenLastCalledWith({
      phase: 'filtering',
      completed: 5000,
      total: 5000,
    });
    const controller = new AbortController();
    await expect(
      indexAuditEvents(source, controller.signal, (value) => {
        if (value.completed === 4096) {
          controller.abort();
        }
      }),
    ).rejects.toMatchObject({ code: 'cancelled' });
    const filtering = new AbortController();
    await expect(
      auditEventPage(index, 0, 'work', null, true, filtering.signal, undefined, (value) => {
        if (value.completed === 4096) {
          filtering.abort();
        }
      }),
    ).rejects.toMatchObject({ code: 'cancelled' });
    expect(animation).not.toHaveBeenCalled();
  } finally {
    animation.mockRestore();
  }
});
it('indexes verified JSONL in bounded primitive arrays and uses native predicates across all pages', async () => {
  const source = new Blob(
    Array.from({ length: 45 }, (_, index) => `${JSON.stringify(record(index))}\n`),
  );
  const controller = new AbortController();
  const index = await indexAuditEvents(source, controller.signal);
  expect(index.count).toBe(45);
  expect(index.offsets).toBeInstanceOf(Uint32Array);
  expect(index.times).toBeInstanceOf(Float64Array);
  const first = await auditEventPage(index, 0, '', null, true, controller.signal);
  expect(first.items).toHaveLength(20);
  expect(first.items[0]?.record.id).toBe('event-44');
  expect(first.next).toBe('next');
  const final = await auditEventPage(index, 2, '', null, true, controller.signal);
  expect(final.items).toHaveLength(5);
  expect(final.next).toBe('');
  expect(final.items.at(-1)?.record.id).toBe('event-0');
  const filtered = await auditEventPage(
    index,
    0,
    'work',
    { field: 'outcome', operator: 'equals', value: 'DENIED' },
    false,
    controller.signal,
  );
  expect(filtered.items).toHaveLength(15);
  expect(filtered.items.every((row) => row.outcome === 'denied')).toBe(true);
  expect(filtered.items[0]?.record.id).toBe('event-0');
  controller.abort();
  await expect(auditEventPage(index, 0, '', null, true, controller.signal)).rejects.toMatchObject({
    code: 'cancelled',
  });
});
it('handles UTF-8 byte offsets without changing or retaining original event bytes', async () => {
  const value = {
    ...record(0),
    event: { name: 'session.task.completed', flow: 'äö漢字', outcome: 'success' },
  };
  const source = new Blob([`${JSON.stringify(value)}\n${JSON.stringify(record(1))}\n`]);
  const original = await source.text();
  const index = await indexAuditEvents(source, new AbortController().signal);
  const page = await auditEventPage(index, 0, 'äö', null, false, new AbortController().signal);
  expect(page.items).toHaveLength(1);
  expect(page.items[0]?.flow).toBe('äö漢字');
  expect(await source.text()).toBe(original);
});
it('binds route flow selectors literally and finds ID shortcuts across the verified source without guessing duplicates', async () => {
  const id = '34e34ab8-7457-4d88-a5e4-c57791775c3a';
  const other = '70d5159d-a0e4-46ca-b011-c4f831f4ade0';
  const source = new Blob(
    [
      {
        id,
        recordedAt: '2026-11-05T00:00:00Z',
        event: { name: 'session.task.completed', flow: 'Docker' },
      },
      {
        id,
        recordedAt: '2026-11-05T00:01:00Z',
        event: { name: 'session.task.completed', flow: 'docker' },
      },
      { id: other, recordedAt: '2026-11-05T00:02:00Z', event: { name: 'session.task.completed' } },
    ].map((row) => `${JSON.stringify(row)}\n`),
  );
  const signal = new AbortController().signal;
  const index = await indexAuditEvents(source, signal);
  expect(
    (
      await auditEventPage(
        index,
        0,
        '',
        { field: 'flow', operator: 'equals', value: 'Docker' },
        false,
        signal,
        'Docker',
      )
    ).items.map((row) => row.flow),
  ).toEqual(['Docker']);
  expect(
    (
      await auditEventPage(
        index,
        0,
        '',
        { field: 'flow', operator: 'isEmpty', value: '' },
        false,
        signal,
        '-',
        undefined,
        undefined,
        true,
      )
    ).items.map((row) => row.record.id),
  ).toEqual([other]);
  expect((await auditEventByID(index, id, signal, 'Docker'))?.flow).toBe('Docker');
  await expect(auditEventByID(index, id, signal)).rejects.toMatchObject({ code: 'verification' });
  expect(await auditEventByID(index, other, signal, 'Docker')).toBeNull();
  expect(await auditEventByID(index, other, signal, '-')).toBeNull();
  expect((await auditEventByID(index, other, signal, '-', undefined, undefined, true))?.flow).toBe(
    '',
  );
});
