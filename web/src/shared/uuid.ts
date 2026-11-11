const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function uuidBytes(value: unknown): Uint8Array<ArrayBuffer> | null {
  if (typeof value !== 'string') {
    return null;
  }
  let hex = value;
  if (hex.length === 45 && /^urn:uuid:/iu.test(hex)) {
    hex = hex.slice(9);
  }
  if (hex.length === 38 && hex.startsWith('{') && hex.endsWith('}')) {
    hex = hex.slice(1, -1);
  }
  if (/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/iu.test(hex) || /^[0-9a-f]{32}$/iu.test(hex)) {
    hex = hex.replaceAll('-', '');
    return Uint8Array.from({ length: 16 }, (_, index) =>
      Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16),
    );
  }
  if (value.length < 16 || value.length > 22) {
    return null;
  }
  let number = 0n;
  for (const char of value) {
    const digit = alphabet.indexOf(char);
    if (digit < 0) {
      return null;
    }
    number = number * 58n + BigInt(digit);
  }
  const bytes = [];
  while (number) {
    bytes.unshift(Number(number & 255n));
    number >>= 8n;
  }
  const zeros = value.match(/^1*/u)?.[0].length ?? 0;
  if (zeros + bytes.length !== 16) {
    return null;
  }
  const result = new Uint8Array(16);
  result.set(bytes, zeros);
  return uuidBase58(result) === value ? result : null;
}

export function uuidBase58(value: Uint8Array): string {
  if (value.byteLength !== 16) {
    throw new Error('Invalid UUID byte length');
  }
  let number = 0n;
  for (const byte of value) {
    number = (number << 8n) | BigInt(byte);
  }
  let result = '';
  while (number) {
    result = alphabet[Number(number % 58n)] + result;
    number /= 58n;
  }
  let zeros = 0;
  while (zeros < value.length && value[zeros] === 0) {
    zeros++;
  }
  return '1'.repeat(zeros) + result;
}
export function uuidText(value: string): string {
  const bytes = uuidBytes(value);
  if (!bytes) {
    throw new Error('Invalid UUID');
  }
  return uuidBase58(bytes);
}
export function uuidClassic(value: string): string {
  const bytes = uuidBytes(value);
  if (!bytes) {
    throw new Error('Invalid UUID');
  }
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
export function uuidEqual(a: unknown, b: unknown): boolean {
  const left = uuidBytes(a);
  const right = uuidBytes(b);
  return !!left && !!right && left.every((value, index) => value === right[index]);
}
export function resourceID(value: unknown): value is string {
  const bytes = uuidBytes(value);
  return !!bytes && bytes.some((byte) => byte !== 0);
}
export const newViewID = () => uuidText(crypto.randomUUID());
export const uuidInputPattern =
  '(?:[1-9A-HJ-NP-Za-km-z]{16,22}|[0-9A-Fa-f]{32}|[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}|\\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\\}|urn:uuid:[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})';
