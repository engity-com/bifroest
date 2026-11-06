// Accept only this fixed, bounded public condition. Never retain, print, or
// surface a server's arbitrary error text, path, response object, or cause.
export function isCatalogWarmupResponse(value: unknown): boolean {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(',') !== 'code,error'
  ) {
    return false;
  }
  const code = Object.getOwnPropertyDescriptor(value, 'code');
  const error = Object.getOwnPropertyDescriptor(value, 'error');
  return (
    code !== undefined &&
    'value' in code &&
    code.value === 'recording-catalog-incomplete' &&
    error !== undefined &&
    'value' in error &&
    error.value === 'recording catalog verification incomplete; refresh to continue'
  );
}
