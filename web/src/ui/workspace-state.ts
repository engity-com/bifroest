// Owner IDs identify mounted management views, not users/roles or permissions.
// Clearing one view's preparation/cleanup must not release another view's lock.
export function ownerLocks(
  previous: ReadonlySet<number>,
  owner: number,
  locked: boolean,
): ReadonlySet<number> {
  const next = new Set(previous);
  if (locked) {
    next.add(owner);
  } else {
    next.delete(owner);
  }
  return next;
}

export function canCloseView(
  blocked: boolean,
  focusBlocked: boolean,
  owners: ReadonlySet<number>,
): boolean {
  return !blocked && !focusBlocked && owners.size === 0;
}
