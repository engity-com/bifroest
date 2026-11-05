import { expect, it } from 'vitest';
import { auditEventPage, indexAuditEvents } from '../src/artifacts/audit-events';

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
