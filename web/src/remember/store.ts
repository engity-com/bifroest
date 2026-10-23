import { encode64, proofBytes, RememberMeError, validateBinding, validateScope } from './protocol';
import type { Binding, ProofPurpose, Scope } from './protocol';

const databaseName = 'bifroest-browser-remember-v1';
const objectStore = 'bindings';
const schema = 'bifroest-browser-state-v1';
const encoder = new TextEncoder();

interface Keys {
  signing: CryptoKeyPair;
  encryption: CryptoKey;
}

interface RecordValue extends Keys {
  tag: string;
  generation: string;
  iv: Uint8Array<ArrayBuffer>;
  ciphertext: ArrayBuffer;
}

interface State {
  schema: typeof schema;
  scope: Scope;
  binding: Binding | null;
}

function sameScope(left: Scope, right: Scope): boolean {
  return left.origin === right.origin && left.slug === right.slug;
}

function validateKeys(keys: Keys): void {
  const { privateKey, publicKey } = keys.signing;
  const encryption = keys.encryption;
  if (!(privateKey instanceof CryptoKey) || privateKey.type !== 'private' || privateKey.extractable ||
      privateKey.algorithm.name !== 'ECDSA' || (privateKey.algorithm as EcKeyAlgorithm).namedCurve !== 'P-256' ||
      privateKey.usages.length !== 1 || privateKey.usages[0] !== 'sign' ||
      !(publicKey instanceof CryptoKey) || publicKey.type !== 'public' || publicKey.algorithm.name !== 'ECDSA' ||
      (publicKey.algorithm as EcKeyAlgorithm).namedCurve !== 'P-256' ||
      publicKey.usages.length !== 1 || publicKey.usages[0] !== 'verify' ||
      !(encryption instanceof CryptoKey) || encryption.type !== 'secret' || encryption.extractable ||
      encryption.algorithm.name !== 'AES-GCM' || (encryption.algorithm as AesKeyAlgorithm).length !== 256 ||
      encryption.usages.length !== 2 || !encryption.usages.includes('encrypt') || !encryption.usages.includes('decrypt')) {
    throw new RememberMeError('unavailable');
  }
}

async function scopeTag(scope: Scope): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(`${schema}\0${scope.origin}\0${scope.slug}`));
  return Array.from(new Uint8Array(digest), n => n.toString(16).padStart(2, '0')).join('');
}

function associatedData(record: Pick<RecordValue, 'tag' | 'generation'>): Uint8Array<ArrayBuffer> {
  return encoder.encode(`${schema}\0${record.tag}\0${record.generation}`);
}

async function encrypt(record: Pick<RecordValue, 'tag' | 'generation'> & Keys, state: State): Promise<RecordValue> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: associatedData(record) }, record.encryption, encoder.encode(JSON.stringify(state)));
  return { tag: record.tag, generation: record.generation, signing: record.signing, encryption: record.encryption, iv, ciphertext };
}

async function decrypt(record: RecordValue, scope: Scope): Promise<State> {
  if (Object.keys(record).sort().join(',') !== 'ciphertext,encryption,generation,iv,signing,tag' ||
      Object.keys(record.signing).sort().join(',') !== 'privateKey,publicKey') throw new RememberMeError('unavailable');
  validateKeys(record);
  if (record.tag !== await scopeTag(scope) || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(record.generation) ||
      !(record.iv instanceof Uint8Array) || record.iv.byteLength !== 12 ||
      !(record.ciphertext instanceof ArrayBuffer) || record.ciphertext.byteLength > 8192) throw new RememberMeError('unavailable');
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: record.iv, additionalData: associatedData(record) }, record.encryption, record.ciphertext);
  const state = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)) as State;
  if (Object.keys(state).sort().join(',') !== 'binding,schema,scope' || state.schema !== schema ||
      Object.keys(state.scope).sort().join(',') !== 'origin,slug' || !sameScope(state.scope, scope)) throw new RememberMeError('unavailable');
  if (state.binding !== null) {
    if (Object.keys(state.binding).sort().join(',') !== 'bindingId,flow,sessionId') throw new RememberMeError('unavailable');
    validateBinding(state.binding);
  }
  const check = encoder.encode(`bifroest-browser-key-check-v1\0${crypto.randomUUID()}`);
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, record.signing.privateKey, check);
  if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, record.signing.publicKey, signature, check)) throw new RememberMeError('unavailable');
  return state;
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let blocked = false;
    const request = indexedDB.open(databaseName, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(objectStore, { keyPath: 'tag' });
    request.onblocked = () => { blocked = true; reject(new RememberMeError('unavailable')); };
    request.onerror = () => reject(new RememberMeError('unavailable'));
    request.onsuccess = () => {
      if (blocked) { request.result.close(); return; }
      request.result.onversionchange = () => request.result.close();
      resolve(request.result);
    };
  });
}

// No crypto/network awaits inside an IndexedDB transaction: browsers may
// auto-commit it while the event loop is processing an unrelated operation.
async function transact<T>(mode: IDBTransactionMode, action: (store: IDBObjectStore, result: (value: T) => void, fail: () => void) => void): Promise<T> {
  const db = await openDatabase();
  try {
    return await new Promise<T>((resolve, reject) => {
      const transaction = db.transaction(objectStore, mode);
      let value: T;
      transaction.oncomplete = () => resolve(value);
      transaction.onerror = transaction.onabort = () => reject(new RememberMeError('unavailable'));
      const fail = () => { transaction.abort(); };
      try { action(transaction.objectStore(objectStore), result => { value = result; }, fail); }
      catch { transaction.abort(); }
    });
  } finally { db.close(); }
}

async function read(tag: string): Promise<RecordValue | undefined> {
  return transact('readonly', (store, result) => {
    const request = store.get(tag);
    request.onsuccess = () => result(request.result as RecordValue | undefined);
  });
}

async function replace(record: RecordValue, expected: string | undefined): Promise<void> {
  let changed = false;
  await transact<void>('readwrite', (store, _result, fail) => {
    const request = store.get(record.tag);
    request.onsuccess = () => {
      const current = request.result as RecordValue | undefined;
      if (expected === undefined ? current !== undefined : current?.generation !== expected) { changed = true; fail(); return; }
      store.put(record);
    };
  }).catch(error => { if (changed) throw new RememberMeError('changed'); throw error; });
}

// A tab-local capability over structured-cloned non-exportable keys. It contains
// no primary login key/password or ephemeral bwa1/bwl1/bwr1 permission.
export class BrowserBinding {
  readonly scope: Scope;
  readonly binding: Binding | null;
  readonly #record: RecordValue;
  private constructor(scope: Scope, binding: Binding | null, record: RecordValue) {
    this.scope = Object.freeze({ ...scope });
    this.binding = binding === null ? null : Object.freeze({ flow: binding.flow, sessionId: binding.sessionId, bindingId: binding.bindingId });
    this.#record = record;
    Object.freeze(this);
  }

  static async prepare(scope: Scope, options: { explicitOptIn: boolean }): Promise<BrowserBinding> {
    if (options?.explicitOptIn !== true) throw new RememberMeError('opt-in-required');
    validateScope(scope);
    scope = { origin: scope.origin, slug: scope.slug };
    try {
      const [signing, encryption] = await Promise.all([
        crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']),
        crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
      ]);
      const record = await encrypt({ tag: await scopeTag(scope), generation: crypto.randomUUID(), signing, encryption }, { schema, scope: { ...scope }, binding: null });
      // Persist keys BEFORE any enrollment request can create a server binding.
      await replace(record, undefined);
      // A real structured-clone roundtrip is required; memory-only CryptoKeys or
      // private-key export/import are not a fallback for unsupported browsers.
      const stored = await BrowserBinding.load(scope);
      if (stored === null) throw new RememberMeError('unavailable');
      if (stored.#record.generation !== record.generation) throw new RememberMeError('changed');
      return stored;
    } catch (error) { throw error instanceof RememberMeError ? error : new RememberMeError('unavailable'); }
  }

  static async load(scope: Scope): Promise<BrowserBinding | null> {
    validateScope(scope);
    scope = { origin: scope.origin, slug: scope.slug };
    try {
      const record = await read(await scopeTag(scope));
      if (record === undefined) return null;
      const state = await decrypt(record, scope);
      return new BrowserBinding(scope, state.binding, record);
    } catch { throw new RememberMeError('unavailable'); }
  }

  async publicKey(): Promise<string> {
    try { return encode64(new Uint8Array(await crypto.subtle.exportKey('raw', this.#record.signing.publicKey))); }
    catch { throw new RememberMeError('unavailable'); }
  }

  async sign(challenge: string, purpose: ProofPurpose): Promise<string> {
    if ((purpose === 'enroll') !== (this.binding === null)) throw new RememberMeError('invalid-proof');
    const bytes = proofBytes(challenge, this.scope, await this.publicKey(), purpose, this.binding ?? undefined);
    try {
      const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.#record.signing.privateKey, bytes));
      if (signature.byteLength !== 64) throw new Error();
      return encode64(signature);
    } catch { throw new RememberMeError('unavailable'); }
  }

  async complete(binding: Binding): Promise<BrowserBinding> {
    if (this.binding !== null) throw new RememberMeError('changed');
    validateBinding(binding);
    try {
      const selected = { flow: binding.flow, sessionId: binding.sessionId, bindingId: binding.bindingId };
      const record = await encrypt({ ...this.#record, generation: crypto.randomUUID() }, { schema, scope: this.scope, binding: selected });
      await replace(record, this.#record.generation);
      return new BrowserBinding(this.scope, selected, record);
    } catch (error) { throw error instanceof RememberMeError ? error : new RememberMeError('unavailable'); }
  }

  // Local deletion ONLY, not server revoke/logout. The API/UI must durably
  // revoke first (or explicitly explain a failed remote revoke) before calling.
  async forgetLocal(): Promise<void> {
    let changed = false;
    await transact<void>('readwrite', (store, _result, fail) => {
      const request = store.get(this.#record.tag);
      request.onsuccess = () => {
        const current = request.result as RecordValue | undefined;
        if (current !== undefined && current.generation !== this.#record.generation) { changed = true; fail(); return; }
        store.delete(this.#record.tag);
      };
    }).catch(error => { if (changed) throw new RememberMeError('changed'); throw error; });
  }
}
