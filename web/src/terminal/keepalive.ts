import { object } from '../remember/http';
import { RememberMeError } from '../remember/protocol';

export interface KeepAlivePolicy {
  readonly interval: string;
  readonly locked: boolean;
}
export const defaultKeepAlive: KeepAlivePolicy = Object.freeze({ interval: '15s', locked: false });

// Match Go duration syntax and nanosecond truncation without floating-point
// rounding at the 1s/5m policy bounds. The server remains authoritative.
export function keepAliveDuration(value: unknown): bigint | null {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 64 ||
    new TextEncoder().encode(value).byteLength > 64
  ) {
    return null;
  }
  let rest = value.startsWith('+') ? value.slice(1) : value;
  const units: Record<string, bigint> = {
    ns: 1n,
    us: 1000n,
    µs: 1000n,
    μs: 1000n,
    ms: 1000000n,
    s: 1000000000n,
    m: 60000000000n,
    h: 3600000000000n,
  };
  let total = 0n;
  while (rest.length) {
    const part = /^(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)/u.exec(rest);
    if (!part) {
      return null;
    }
    const [whole = '0', fraction = ''] = (part[1] ?? '').split('.');
    const scale = units[part[2] ?? ''];
    if (scale === undefined) {
      return null;
    }
    total +=
      BigInt(whole || '0') * scale +
      (BigInt(fraction || '0') * scale) / 10n ** BigInt(fraction.length);
    if (total > 300000000000n) {
      return null;
    }
    rest = rest.slice(part[0].length);
  }
  return total >= 1000000000n ? total : null;
}

export function keepAlivePolicy(value: unknown): KeepAlivePolicy {
  const policy = object(value, ['interval', 'locked']);
  if (keepAliveDuration(policy.interval) === null || typeof policy.locked !== 'boolean') {
    throw new RememberMeError('unavailable');
  }
  return Object.freeze({ interval: policy.interval as string, locked: policy.locked });
}
