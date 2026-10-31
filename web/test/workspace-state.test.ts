import { expect, it } from 'vitest';
import { canCloseView, ownerLocks } from '../src/ui/workspace-state';

it('aggregates per-view action locks without letting a sibling mount/cleanup/dismiss unlock another owner', () => {
  const empty = new Set<number>();
  const a = ownerLocks(empty, 1, true);
  expect([...empty]).toEqual([]);
  expect([...ownerLocks(a, 2, false)]).toEqual([1]);
  const both = ownerLocks(a, 2, true);
  expect([...ownerLocks(both, 2, false)]).toEqual([1]);
  expect([...ownerLocks(both, 1, false)]).toEqual([2]);
  expect([...ownerLocks(ownerLocks(both, 1, false), 2, false)]).toEqual([]);
});

it('rejects an earlier close intent when a later owner lock, block or foreign modal is active', () => {
  const empty = new Set<number>();
  expect(canCloseView(false, false, empty)).toBe(true);
  expect(canCloseView(true, false, empty)).toBe(false);
  expect(canCloseView(false, true, empty)).toBe(false);
  const lockedLater = ownerLocks(empty, 1, true);
  expect(canCloseView(false, false, lockedLater)).toBe(false);
  expect(canCloseView(false, false, ownerLocks(lockedLater, 2, false))).toBe(false);
  expect(canCloseView(false, false, ownerLocks(lockedLater, 1, false))).toBe(true);
});
