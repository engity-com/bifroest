import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Binding, ProofPurpose, Scope } from '../src/remember';
import { BrowserBinding, RememberMeError } from '../src/remember';
import { decode64, encode64 } from '../src/remember/protocol';
import { required } from './required';

const database = 'bifroest-browser-remember-v1';
const scope: Scope = { origin: 'https://app.example.org:8443', slug: 'Work' };
const binding: Binding = {
  flow: 'Sensitive.Project-1',
  sessionId: '70d5159d-a0e4-46ca-b011-c4f831f4ade0',
  bindingId: `bbr1.${'A'.repeat(43)}`,
};

interface RawRecord {
  [field: string]: unknown;
  tag: string;
  generation: string;
  signing: CryptoKeyPair;
  encryption: CryptoKey;
  iv: Uint8Array<ArrayBuffer>;
  ciphertext: ArrayBuffer;
}

async function deleteDatabase(): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(database);
    request.onsuccess = () => resolve();
    request.onerror = request.onblocked = () => reject(new Error('test database blocked'));
  });
}

async function rawRecord(change?: (record: RawRecord) => void): Promise<RawRecord> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(database, 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction('bindings', change === undefined ? 'readonly' : 'readwrite');
      let record: RawRecord;
      const request = tx.objectStore('bindings').getAll();
      request.onsuccess = () => {
        record = request.result[0];
        if (change !== undefined) {
          change(record);
          tx.objectStore('bindings').put(record);
        }
      };
      tx.oncomplete = () => resolve(record);
      tx.onerror = tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

async function challenge(
  handle: BrowserBinding,
  purpose: ProofPurpose,
  changes: Record<string, unknown> = {},
): Promise<string> {
  return encode64(
    new TextEncoder().encode(
      'bifroest-browser-remember-v1\0' +
        JSON.stringify({
          purpose,
          origin: scope.origin,
          slug: scope.slug,
          flow: binding.flow,
          sessionId: binding.sessionId,
          bindingId: purpose === 'enroll' ? '' : binding.bindingId,
          revision: purpose === 'enroll' ? 0 : 1,
          target: 'f'.repeat(64),
          publicKey: await handle.publicKey(),
          nonce: encode64(crypto.getRandomValues(new Uint8Array(32))),
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          ...changes,
        }),
    ),
  );
}

beforeEach(deleteDatabase);

describe('real browser RememberMe keys and IndexedDB', () => {
  it('requires explicit opt-in before creating any database or key state', async () => {
    await expect(BrowserBinding.prepare(scope, { explicitOptIn: false })).rejects.toMatchObject({
      code: 'opt-in-required',
    });
    expect((await indexedDB.databases()).some((db) => db.name === database)).toBe(false);
  });

  it('structured-clones independent non-exportable keys and persists only encrypted selectors', async () => {
    const pending = await BrowserBinding.prepare(scope, { explicitOptIn: true });
    const initial = await rawRecord();
    expect(initial.signing.privateKey).toBeInstanceOf(CryptoKey);
    expect(initial.signing.privateKey.extractable).toBe(false);
    expect(initial.encryption.extractable).toBe(false);
    expect(initial.signing.privateKey.algorithm).toMatchObject({
      name: 'ECDSA',
      namedCurve: 'P-256',
    });
    expect(initial.encryption.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    await expect(
      crypto.subtle.exportKey('pkcs8', initial.signing.privateKey),
    ).rejects.toBeInstanceOf(DOMException);
    await expect(crypto.subtle.exportKey('raw', initial.encryption)).rejects.toBeInstanceOf(
      DOMException,
    );
    const ready = await pending.complete(binding);
    expect(ready.binding).toEqual(binding);
    const record = await rawRecord();
    expect(record.generation).not.toBe(initial.generation);
    expect(Array.from(record.iv)).not.toEqual(Array.from(initial.iv));
    expect(Object.keys(record).sort()).toEqual([
      'ciphertext',
      'encryption',
      'generation',
      'iv',
      'signing',
      'tag',
    ]);
    const visible = JSON.stringify(record) + new TextDecoder().decode(record.ciphertext);
    for (const value of [
      scope.origin,
      scope.slug,
      binding.flow,
      binding.sessionId,
      binding.bindingId,
    ]) {
      expect(visible).not.toContain(value);
    }
    const loaded = await BrowserBinding.load(scope);
    expect(loaded?.binding).toEqual(binding);
    expect(await loaded?.publicKey()).toBe(await ready.publicKey());
    expect(document.cookie).toBe('');
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it('signs original server bytes with P1363 after a fresh IndexedDB roundtrip', async () => {
    const pending = await BrowserBinding.prepare(scope, { explicitOptIn: true });
    const enrollment = await challenge(pending, 'enroll');
    const proof = decode64(await pending.sign(enrollment, 'enroll'), 64);
    expect(proof.length).toBe(64);
    const publicKey = await crypto.subtle.importKey(
      'raw',
      decode64(await pending.publicKey(), 65),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    expect(
      await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        proof,
        decode64(enrollment, 16 << 10),
      ),
    ).toBe(true);
    await pending.complete(binding);
    const loaded = required(await BrowserBinding.load(scope));
    for (const purpose of ['resume', 'revoke'] as const) {
      const encoded = await challenge(loaded, purpose);
      const signature = decode64(await loaded.sign(encoded, purpose), 64);
      expect(
        await crypto.subtle.verify(
          { name: 'ECDSA', hash: 'SHA-256' },
          publicKey,
          signature,
          decode64(encoded, 16 << 10),
        ),
      ).toBe(true);
    }
  });

  it('never signs another purpose, origin, slug, key, session or binding', async () => {
    const pending = await BrowserBinding.prepare(scope, { explicitOptIn: true });
    await expect(pending.sign(await challenge(pending, 'resume'), 'resume')).rejects.toMatchObject({
      code: 'invalid-proof',
    });
    const ready = await pending.complete(binding);
    for (const changes of [
      { purpose: 'revoke' },
      { origin: 'https://other.example.org' },
      { origin: 'https://app.example.org' },
      { slug: 'Other' },
      { publicKey: 'wrong' },
      { flow: 'other' },
      { sessionId: crypto.randomUUID() },
      { bindingId: `bbr1.${'B'.repeat(43)}` },
      { revision: 0 },
      { revision: Number.MAX_SAFE_INTEGER + 1 },
      { target: 'wrong' },
      { nonce: '' },
      { extra: true },
    ]) {
      await expect(
        ready.sign(await challenge(ready, 'resume', changes), 'resume'),
      ).rejects.toMatchObject({ code: 'invalid-proof' });
    }
    await expect(ready.sign(await challenge(ready, 'enroll'), 'enroll')).rejects.toMatchObject({
      code: 'invalid-proof',
    });
    await expect(
      ready.sign(encode64(new TextEncoder().encode('bifroest-http-public-key-v1\0{}')), 'resume'),
    ).rejects.toMatchObject({ code: 'invalid-proof' });
    for (const other of [
      { ...scope, origin: 'https://other.example.org' },
      { ...scope, slug: 'Other' },
      { ...scope, origin: 'https://app.example.org' },
    ]) {
      expect(await BrowserBinding.load(other)).toBeNull();
    }
  });

  it('allows only one concurrent enrollment or completion and rejects stale deletion', async () => {
    const attempts = await Promise.allSettled(
      Array.from({ length: 4 }, () => BrowserBinding.prepare(scope, { explicitOptIn: true })),
    );
    expect(attempts.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    for (const attempt of attempts) {
      if (attempt.status === 'rejected') {
        expect(attempt.reason).toMatchObject({ code: 'changed' });
      }
    }
    const pending = required(await BrowserBinding.load(scope));
    const completion = await Promise.allSettled([
      pending.complete(binding),
      pending.complete({ ...binding, sessionId: crypto.randomUUID() }),
    ]);
    expect(completion.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    await expect(pending.forgetLocal()).rejects.toMatchObject({ code: 'changed' });
    const ready = required(await BrowserBinding.load(scope));
    await ready.forgetLocal();
    expect(await BrowserBinding.load(scope)).toBeNull();
    const replacement = await BrowserBinding.prepare(scope, { explicitOptIn: true });
    await expect(ready.forgetLocal()).rejects.toMatchObject({ code: 'changed' });
    expect(await (await BrowserBinding.load(scope))?.publicKey()).toBe(
      await replacement.publicKey(),
    );
  });

  it('missing storage/keys require regular login; corrupt state is never repaired or exported', async () => {
    expect(await BrowserBinding.load(scope)).toBeNull();
    const pending = await BrowserBinding.prepare(scope, { explicitOptIn: true });
    await pending.complete(binding);
    const original = await rawRecord();
    for (const change of [
      (record: RawRecord) => {
        Reflect.set(record.signing, 'privateKey', null);
      },
      (record: RawRecord) => {
        Reflect.set(record, 'encryption', null);
      },
      (record: RawRecord) => {
        record.iv[0] = required(record.iv[0]) ^ 1;
      },
      (record: RawRecord) => {
        const bytes = new Uint8Array(record.ciphertext);
        bytes[0] = required(bytes[0]) ^ 1;
      },
      (record: RawRecord) => {
        record.generation = crypto.randomUUID();
      },
    ]) {
      await rawRecord((record) => {
        Object.assign(record, structuredClone(original));
        change(record);
      });
      const damaged = await rawRecord();
      await expect(BrowserBinding.load(scope)).rejects.toBeInstanceOf(RememberMeError);
      expect((await rawRecord()).generation).toBe(damaged.generation);
      expect(Array.from(new Uint8Array((await rawRecord()).ciphertext))).toEqual(
        Array.from(new Uint8Array(damaged.ciphertext)),
      );
    }
    const mismatched = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify'],
    );
    await rawRecord((record) => {
      Object.assign(record, structuredClone(original));
      record.signing.publicKey = mismatched.publicKey;
    });
    await expect(BrowserBinding.load(scope)).rejects.toMatchObject({ code: 'unavailable' });
  });

  it('does not fall back to exported or memory-only keys when browser persistence fails', async () => {
    const blocked = vi.spyOn(IDBFactory.prototype, 'open').mockImplementation(() => {
      throw new DOMException('private browser diagnostic', 'SecurityError');
    });
    try {
      await expect(BrowserBinding.prepare(scope, { explicitOptIn: true })).rejects.toMatchObject({
        code: 'unavailable',
        message: 'Browser RememberMe: unavailable',
      });
    } finally {
      blocked.mockRestore();
    }
    expect(await BrowserBinding.load(scope)).toBeNull();
  });

  it('does not repair or overwrite malformed existing records, including missing generations', async () => {
    await BrowserBinding.prepare(scope, { explicitOptIn: true });
    await rawRecord((record) => {
      Reflect.deleteProperty(record, 'generation');
      record.unexpected = 'private diagnostic';
    });
    const before = await rawRecord();
    await expect(BrowserBinding.load(scope)).rejects.toMatchObject({ code: 'unavailable' });
    await expect(BrowserBinding.prepare(scope, { explicitOptIn: true })).rejects.toMatchObject({
      code: 'changed',
    });
    const after = await rawRecord();
    expect(after.generation).toBeUndefined();
    expect(after.unexpected).toBe('private diagnostic');
    expect(Array.from(new Uint8Array(after.ciphertext))).toEqual(
      Array.from(new Uint8Array(before.ciphertext)),
    );
  });

  it('rejects persistent secret/token/rights fields and noncanonical scope aliases', async () => {
    for (const changed of [
      { ...scope, origin: 'http://app.example.org' },
      { ...scope, origin: 'https://APP.example.org:8443' },
      { ...scope, origin: 'https://app.example.org:443' },
      { ...scope, origin: 'https://app.example.org.' },
      { ...scope, slug: 'Work/' },
      { ...scope, accessToken: 'bwa1.secret' },
    ]) {
      await expect(BrowserBinding.prepare(changed, { explicitOptIn: true })).rejects.toMatchObject({
        code: 'unavailable',
      });
    }
    const pending = await BrowserBinding.prepare(scope, { explicitOptIn: true });
    for (const field of [
      'privateKey',
      'password',
      'accessToken',
      'attemptToken',
      'authorization',
    ]) {
      await expect(
        pending.complete({ ...binding, [field]: 'must-not-persist' }),
      ).rejects.toMatchObject({ code: 'unavailable' });
    }
    expect((await BrowserBinding.load(scope))?.binding).toBeNull();
  });
});
