/** Fail a test fixture explicitly instead of hiding a missing value behind `!`. */
export function required<T>(value: T | null | undefined): T {
  if (value === null || value === undefined) {
    throw new Error('Required test fixture value is missing');
  }
  return value;
}
