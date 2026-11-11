import { newViewID, resourceID } from '../shared/uuid';
import type { Binding, ProofPurpose, Scope } from './protocol';
import { encode64, proofBytes, RememberMeError, validateBinding, validateScope } from './protocol';

const databaseName = 'bifroest-browser-remember-v1';
const objectStore = 'bindings';
const metadataStore = 'metadata';
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
  if (
    !(privateKey instanceof CryptoKey) ||
    privateKey.type !== 'private' ||
    privateKey.extractable ||
    privateKey.algorithm.name !== 'ECDSA' ||
    (privateKey.algorithm as EcKeyAlgorithm).namedCurve !== 'P-256' ||
    privateKey.usages.length !== 1 ||
    privateKey.usages[0] !== 'sign' ||
    !(publicKey instanceof CryptoKey) ||
    publicKey.type !== 'public' ||
    publicKey.algorithm.name !== 'ECDSA' ||
    (publicKey.algorithm as EcKeyAlgorithm).namedCurve !== 'P-256' ||
    publicKey.usages.length !== 1 ||
    publicKey.usages[0] !== 'verify' ||
    !(encryption instanceof CryptoKey) ||
    encryption.type !== 'secret' ||
    encryption.extractable ||
    encryption.algorithm.name !== 'AES-GCM' ||
    (encryption.algorithm as AesKeyAlgorithm).length !== 256 ||
    encryption.usages.length !== 2 ||
    !encryption.usages.includes('encrypt') ||
    !encryption.usages.includes('decrypt')
  ) {
    throw new RememberMeError('unavailable');
  }
}

async function scopeTag(scope: Scope): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    encoder.encode(`${schema}\0${scope.origin}\0${scope.slug}`),
  );
  return Array.from(new Uint8Array(digest), (n) => n.toString(16).padStart(2, '0')).join('');
}

function associatedData(record: Pick<RecordValue, 'tag' | 'generation'>): Uint8Array<ArrayBuffer> {
  return encoder.encode(`${schema}\0${record.tag}\0${record.generation}`);
}

async function encrypt(
  record: Pick<RecordValue, 'tag' | 'generation'> & Keys,
  state: State,
): Promise<RecordValue> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: associatedData(record) },
    record.encryption,
    encoder.encode(JSON.stringify(state)),
  );
  return {
    tag: record.tag,
    generation: record.generation,
    signing: record.signing,
    encryption: record.encryption,
    iv,
    ciphertext,
  };
}

async function decrypt(record: RecordValue, scope?: Scope): Promise<State> {
  if (
    Object.keys(record).sort().join(',') !== 'ciphertext,encryption,generation,iv,signing,tag' ||
    Object.keys(record.signing).sort().join(',') !== 'privateKey,publicKey'
  ) {
    throw new RememberMeError('unavailable');
  }
  validateKeys(record);
  if (
    typeof record.tag !== 'string' ||
    !/^[0-9a-f]{64}$/u.test(record.tag) ||
    (scope !== undefined && record.tag !== (await scopeTag(scope))) ||
    !resourceID(record.generation) ||
    !(record.iv instanceof Uint8Array) ||
    record.iv.byteLength !== 12 ||
    !(record.ciphertext instanceof ArrayBuffer) ||
    record.ciphertext.byteLength > 8192
  ) {
    throw new RememberMeError('unavailable');
  }
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: record.iv, additionalData: associatedData(record) },
    record.encryption,
    record.ciphertext,
  );
  const state = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)) as State;
  if (
    Object.keys(state).sort().join(',') !== 'binding,schema,scope' ||
    state.schema !== schema ||
    Object.keys(state.scope).sort().join(',') !== 'origin,slug' ||
    (scope !== undefined && !sameScope(state.scope, scope))
  ) {
    throw new RememberMeError('unavailable');
  }
  validateScope(state.scope);
  if (record.tag !== (await scopeTag(state.scope))) {
    throw new RememberMeError('unavailable');
  }
  if (state.binding !== null) {
    if (Object.keys(state.binding).sort().join(',') !== 'bindingId,flow,sessionId') {
      throw new RememberMeError('unavailable');
    }
    validateBinding(state.binding);
  }
  const check = encoder.encode(`bifroest-browser-key-check-v1\0${newViewID()}`);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    record.signing.privateKey,
    check,
  );
  if (
    !(await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      record.signing.publicKey,
      signature,
      check,
    ))
  ) {
    throw new RememberMeError('unavailable');
  }
  return state;
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let blocked = false;
    const request = indexedDB.open(databaseName, 2);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(objectStore)) {
        request.result.createObjectStore(objectStore, { keyPath: 'tag' });
      }
      if (!request.result.objectStoreNames.contains(metadataStore)) {
        request.result.createObjectStore(metadataStore);
      }
    };
    request.onblocked = () => {
      blocked = true;
      reject(new RememberMeError('unavailable'));
    };
    request.onerror = () => reject(new RememberMeError('unavailable'));
    request.onsuccess = () => {
      if (blocked) {
        request.result.close();
        return;
      }
      request.result.onversionchange = () => request.result.close();
      resolve(request.result);
    };
  });
}

// No crypto/network awaits inside an IndexedDB transaction: browsers may
// auto-commit it while the event loop is processing an unrelated operation.
async function transact<T>(
  mode: IDBTransactionMode,
  action: (store: IDBObjectStore, result: (value: T) => void, fail: () => void) => void,
  expectedReset?: string,
): Promise<T> {
  const db = await openDatabase();
  try {
    return await new Promise<T>((resolve, reject) => {
      const transaction = db.transaction(
        expectedReset === undefined ? objectStore : [objectStore, metadataStore],
        mode,
      );
      let value: T;
      let resetChanged = false;
      transaction.oncomplete = () => resolve(value);
      transaction.onerror = transaction.onabort = () =>
        reject(new RememberMeError(resetChanged ? 'changed' : 'unavailable'));
      const fail = () => {
        transaction.abort();
      };
      const invoke = () => {
        try {
          action(
            transaction.objectStore(objectStore),
            (result) => {
              value = result;
            },
            fail,
          );
        } catch {
          transaction.abort();
        }
      };
      if (expectedReset === undefined) {
        invoke();
      } else {
        const epoch = transaction.objectStore(metadataStore).get('reset');
        epoch.onsuccess = () => {
          if ((epoch.result ?? '') !== expectedReset) {
            resetChanged = true;
            transaction.abort();
          } else {
            invoke();
          }
        };
      }
    });
  } finally {
    db.close();
  }
}

async function read(tag: string): Promise<RecordValue | undefined> {
  return transact('readonly', (store, result) => {
    const request = store.get(tag);
    request.onsuccess = () => result(request.result as RecordValue | undefined);
  });
}

async function replace(
  record: RecordValue,
  expected: string | undefined,
  expectedReset?: string,
): Promise<void> {
  let changed = false;
  await transact<void>(
    'readwrite',
    (store, _result, fail) => {
      const request = store.get(record.tag);
      request.onsuccess = () => {
        const current = request.result as RecordValue | undefined;
        if (expected === undefined ? current !== undefined : current?.generation !== expected) {
          changed = true;
          fail();
          return;
        }
        store.put(record);
      };
    },
    expectedReset,
  ).catch((error) => {
    if (changed) {
      throw new RememberMeError('changed');
    }
    throw error;
  });
}

async function resetGeneration(): Promise<string> {
  const db = await openDatabase();
  try {
    return await new Promise<string>((resolve, reject) => {
      const transaction = db.transaction(metadataStore, 'readonly');
      const request = transaction.objectStore(metadataStore).get('reset');
      let value = '';
      request.onsuccess = () => {
        if (request.result !== undefined && typeof request.result !== 'string') {
          transaction.abort();
        } else {
          value = request.result ?? '';
        }
      };
      transaction.oncomplete = () => resolve(value);
      transaction.onabort = transaction.onerror = () => reject(new RememberMeError('unavailable'));
    });
  } finally {
    db.close();
  }
}

// A tab-local capability over structured-cloned non-exportable keys. It contains
// no primary login key/password or ephemeral bwa1/bwl1/bwr1 permission.
export class BrowserBinding {
  readonly scope: Scope;
  readonly binding: Binding | null;
  readonly #record: RecordValue;
  private constructor(scope: Scope, binding: Binding | null, record: RecordValue) {
    this.scope = Object.freeze({ ...scope });
    this.binding =
      binding === null
        ? null
        : Object.freeze({
            flow: binding.flow,
            sessionId: binding.sessionId,
            bindingId: binding.bindingId,
          });
    this.#record = record;
    Object.freeze(this);
  }

  static async prepare(scope: Scope, options: { explicitOptIn: boolean }): Promise<BrowserBinding> {
    if (options?.explicitOptIn !== true) {
      throw new RememberMeError('opt-in-required');
    }
    validateScope(scope);
    scope = { origin: scope.origin, slug: scope.slug };
    try {
      const reset = await resetGeneration();
      const [signing, encryption] = await Promise.all([
        crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
          'sign',
          'verify',
        ]),
        crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
      ]);
      const record = await encrypt(
        { tag: await scopeTag(scope), generation: newViewID(), signing, encryption },
        { schema, scope: { ...scope }, binding: null },
      );
      // Persist keys BEFORE any enrollment request can create a server binding.
      await replace(record, undefined, reset);
      // A real structured-clone roundtrip is required; memory-only CryptoKeys or
      // private-key export/import are not a fallback for unsupported browsers.
      const stored = await BrowserBinding.load(scope);
      if (stored === null) {
        throw new RememberMeError('unavailable');
      }
      if (stored.#record.generation !== record.generation) {
        throw new RememberMeError('changed');
      }
      return stored;
    } catch (error) {
      throw error instanceof RememberMeError ? error : new RememberMeError('unavailable');
    }
  }

  static async load(scope: Scope): Promise<BrowserBinding | null> {
    validateScope(scope);
    scope = { origin: scope.origin, slug: scope.slug };
    try {
      const record = await read(await scopeTag(scope));
      if (record === undefined) {
        return null;
      }
      const state = await decrypt(record, scope);
      return new BrowserBinding(scope, state.binding, record);
    } catch {
      throw new RememberMeError('unavailable');
    }
  }

  // Explicit origin-wide reset only. Discover scopes by decrypting the existing
  // owned records, not by logging in or querying a server's account inventory.
  static async selectionsForReset(options: {
    origin: string;
    explicitConfirmation: boolean;
  }): Promise<{ handles: BrowserBinding[]; unconfirmed: number }> {
    if (options.explicitConfirmation !== true || options.origin !== location.origin) {
      throw new RememberMeError('opt-in-required');
    }
    const collected = await transact<{ records: RecordValue[]; total: number }>(
      'readonly',
      (store, result) => {
        const state = { records: [] as RecordValue[], total: 0 };
        result(state);
        const count = store.count();
        count.onsuccess = () => {
          state.total = count.result;
        };
        const cursor = store.openCursor();
        cursor.onsuccess = () => {
          const next = cursor.result;
          if (next && state.records.length < 256) {
            state.records.push(next.value as RecordValue);
            next.continue();
          }
        };
      },
    );
    const handles: BrowserBinding[] = [];
    let unconfirmed = Math.max(0, collected.total - collected.records.length);
    for (const record of collected.records) {
      try {
        const state = await decrypt(record);
        if (state.scope.origin !== options.origin || state.binding === null) {
          unconfirmed++;
          continue;
        }
        handles.push(new BrowserBinding(state.scope, state.binding, record));
      } catch {
        unconfirmed++;
      }
    }
    return { handles, unconfirmed };
  }
  static async clearForReset(options: { explicitConfirmation: boolean }): Promise<number> {
    if (options.explicitConfirmation !== true) {
      throw new RememberMeError('opt-in-required');
    }
    const db = await openDatabase();
    try {
      return await new Promise<number>((resolve, reject) => {
        const transaction = db.transaction([objectStore, metadataStore], 'readwrite');
        let removed = 0;
        const count = transaction.objectStore(objectStore).count();
        count.onsuccess = () => {
          removed = count.result;
        };
        transaction.objectStore(metadataStore).put(newViewID(), 'reset');
        transaction.objectStore(objectStore).clear();
        transaction.oncomplete = () => resolve(removed);
        transaction.onabort = transaction.onerror = () =>
          reject(new RememberMeError('unavailable'));
      });
    } finally {
      db.close();
    }
  }

  async publicKey(): Promise<string> {
    try {
      return encode64(
        new Uint8Array(await crypto.subtle.exportKey('raw', this.#record.signing.publicKey)),
      );
    } catch {
      throw new RememberMeError('unavailable');
    }
  }

  async sign(challenge: string, purpose: ProofPurpose): Promise<string> {
    if ((purpose === 'enroll') !== (this.binding === null)) {
      throw new RememberMeError('invalid-proof');
    }
    const bytes = proofBytes(
      challenge,
      this.scope,
      await this.publicKey(),
      purpose,
      this.binding ?? undefined,
    );
    try {
      const signature = new Uint8Array(
        await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          this.#record.signing.privateKey,
          bytes,
        ),
      );
      if (signature.byteLength !== 64) {
        throw new Error();
      }
      return encode64(signature);
    } catch {
      throw new RememberMeError('unavailable');
    }
  }

  async complete(binding: Binding): Promise<BrowserBinding> {
    if (this.binding !== null) {
      throw new RememberMeError('changed');
    }
    validateBinding(binding);
    try {
      const selected = {
        flow: binding.flow,
        sessionId: binding.sessionId,
        bindingId: binding.bindingId,
      };
      const record = await encrypt(
        { ...this.#record, generation: newViewID() },
        { schema, scope: this.scope, binding: selected },
      );
      await replace(record, this.#record.generation);
      return new BrowserBinding(this.scope, selected, record);
    } catch (error) {
      throw error instanceof RememberMeError ? error : new RememberMeError('unavailable');
    }
  }

  // Local deletion ONLY, not server revoke/logout. The API/UI must durably
  // revoke first (or explicitly explain a failed remote revoke) before calling.
  async forgetLocal(): Promise<void> {
    let changed = false;
    await transact<void>('readwrite', (store, _result, fail) => {
      const request = store.get(this.#record.tag);
      request.onsuccess = () => {
        const current = request.result as RecordValue | undefined;
        if (current !== undefined && current.generation !== this.#record.generation) {
          changed = true;
          fail();
          return;
        }
        store.delete(this.#record.tag);
      };
    }).catch((error) => {
      if (changed) {
        throw new RememberMeError('changed');
      }
      throw error;
    });
  }
}
