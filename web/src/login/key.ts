import { loginAttempt } from './interactive';
import { decode64, RememberMeError } from '../remember/protocol';
import { object } from '../remember/http';
import type { Http } from '../remember/http';
import type { Scope } from '../remember/protocol';

// Trusted tab-local adapter, intended for the portable Go core in an owned WASM
// worker. No private key/passphrase or general-purpose signer is a wire field.
// The worker must independently validate context and terminate on close/abort.
export interface LoginKey {
  readonly publicKey: string;
  sign(challenge: string, expiresAt: string, signal: AbortSignal): Promise<string>;
}

const stringToken = '"(?:[^"\\\\\\x00-\\x1f]|\\\\(?:["\\\\/bfnrt]|u[0-9a-fA-F]{4}))*"';
const names = ['origin', 'slug', 'user', 'connectionId', 'publicKeyFingerprint', 'nonce', 'expiresAt'];
// The protocol is a fixed compact flat Go-JSON object. Reject duplicate/unknown
// fields before JSON.parse, but never reconstruct or normalize the signed bytes.
const shape = new RegExp('^\\{' + names.map(name => `"${name}":${stringToken}`).join(',') + '\\}$', 'u');

function checkChallenge(encoded: string, scope: Scope, user: string, fingerprint: string, expiry: string): void {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(decode64(encoded, 8 << 10));
    const prefix = 'bifroest-http-public-key-v1\0';
    if (!text.startsWith(prefix) || !shape.test(text.slice(prefix.length))) throw new Error();
    const body = object(JSON.parse(text.slice(prefix.length)), names);
    if (!names.every(name => typeof body[name] === 'string' && (body[name] as string).isWellFormed()) ||
        body.origin !== scope.origin || body.slug !== scope.slug || body.user !== user || body.publicKeyFingerprint !== fingerprint ||
        typeof body.connectionId !== 'string' || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(body.connectionId) || body.connectionId === '00000000-0000-0000-0000-000000000000' ||
        typeof body.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.nonce) || decode64(body.nonce.replaceAll('-', '+').replaceAll('_', '/') + '=', 32).length !== 32 ||
        body.expiresAt !== expiry || !Number.isFinite(Date.parse(expiry)) || Date.parse(expiry) <= Date.now() || Date.parse(expiry) - Date.now() > 120_000) throw new Error();
  } catch { throw new RememberMeError('invalid-proof'); }
}

function checkSignature(encoded: string): void {
  try {
    const raw = decode64(encoded, 8 << 10);
    let offset = 0;
    const field = () => {
      if (offset + 4 > raw.length) throw new Error();
      const size = new DataView(raw.buffer, raw.byteOffset + offset, 4).getUint32(0); offset += 4;
      if (offset + size > raw.length) throw new Error();
      const value = raw.subarray(offset, offset + size); offset += size; return value;
    };
    const format = new TextDecoder('utf-8', { fatal: true }).decode(field());
    if (!['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-256', 'rsa-sha2-512'].includes(format) || field().length === 0 || offset !== raw.length) throw new Error();
  } catch { throw new RememberMeError('invalid-proof'); }
}

export async function publicKeyLogin(http: Http, scope: Scope, user: string, key: LoginKey, signal?: AbortSignal): Promise<unknown> {
  const publicKey = key.publicKey;
  const bytes = decode64(publicKey, 8 << 10);
  if (bytes.length === 0) throw new RememberMeError('invalid-proof');
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  const fingerprint = 'SHA256:' + btoa(String.fromCharCode(...digest)).replace(/=+$/u, '');
  return loginAttempt(http, user, async (step, expiresAt, stopped) => {
    if (step.kind !== 'public-key') throw new RememberMeError('invalid-step');
    checkChallenge(step.challenge, scope, user, fingerprint, expiresAt);
    const proof = await key.sign(step.challenge, expiresAt, stopped);
    if (stopped.aborted) throw new RememberMeError('cancelled');
    checkSignature(proof);
    return proof;
  }, signal, publicKey);
}
