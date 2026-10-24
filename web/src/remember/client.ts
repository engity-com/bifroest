import { BrowserBinding } from './store';
import { Http, isToken, object, time } from './http';
import { decode64, RememberMeError, validateBinding } from './protocol';
import type { Transport } from './http';
import type { Binding, ProofPurpose, Scope } from './protocol';
import { interactive } from '../login/interactive';
import type { StepHandler } from '../login/interactive';
import { publicKeyLogin } from '../login/key';
import type { LoginKey } from '../login/key';

export interface AccessSnapshot {
  readonly scope: Scope;
  readonly principal: string;
  readonly expiresAt: string;
  readonly environment: 'terminal' | 'management';
  readonly terminalAvailable: boolean;
}

interface AccessResponse extends AccessSnapshot { readonly accessToken: string; }

export interface LogoutResult {
  readonly localState: 'removed' | 'not-owned' | 'changed' | 'unavailable';
}

async function forgetOwned(handle: BrowserBinding | null | undefined): Promise<LogoutResult> {
  if (handle === null || handle === undefined) return { localState: 'not-owned' };
  try { await handle.forgetLocal(); return { localState: 'removed' }; }
  catch (error) { return { localState: error instanceof RememberMeError && error.code === 'changed' ? 'changed' : 'unavailable' }; }
}

function accessResponse(value: unknown, scope: Scope): AccessResponse {
  const body = object(value, ['status', 'accessToken', 'expiresAt', 'scope', 'principal', 'environment', 'terminalAvailable']);
  const selected = object(body.scope, ['origin', 'slug']);
  if (body.status !== 'authorized' || !isToken(body.accessToken, 'bwa1.') || selected.origin !== scope.origin || selected.slug !== scope.slug ||
      typeof body.principal !== 'string' || body.principal.length > 4096 || /[\p{Cc}]/u.test(body.principal) ||
      (body.environment !== 'terminal' && body.environment !== 'management') || body.terminalAvailable !== (body.environment === 'terminal')) throw new RememberMeError('unavailable');
  return { accessToken: body.accessToken, expiresAt: time(body.expiresAt), scope: Object.freeze({ ...scope }), principal: body.principal, environment: body.environment, terminalAvailable: body.terminalAvailable as boolean };
}

async function startProof(http: Http, handle: BrowserBinding, purpose: ProofPurpose, accessToken?: string, signal?: AbortSignal): Promise<{ challenge: string; attemptToken: string }> {
  const fields: Record<string, string> = purpose === 'enroll' ? { publicKey: await handle.publicKey() } : { ...handle.binding! };
  const body = object(await http.post(`remember/${purpose}`, fields, accessToken, 202, signal), ['status', 'attemptToken', 'challenge', 'expiresAt']);
  if (body.status !== 'proof-required' || !isToken(body.attemptToken, 'bwr1.') || typeof body.challenge !== 'string') throw new RememberMeError('unavailable');
  time(body.expiresAt);
  return { challenge: body.challenge, attemptToken: body.attemptToken };
}

async function revoke(http: Http, handle: BrowserBinding, signal?: AbortSignal): Promise<void> {
  if (handle.binding === null) throw new RememberMeError('outcome-unknown');
  const start = await startProof(http, handle, 'revoke', undefined, signal);
  const signature = await handle.sign(start.challenge, 'revoke');
  await http.post('remember/prove', { signature }, start.attemptToken, 204, signal);
}

// This object is an opaque, tab-memory permission, not serializable bearer state.
// Keep one per authenticated UI/execution; a new login does not dispose an old
// execution or implicitly log out unrelated grants/bindings.
export class WebAccess {
  readonly #http: Http;
  readonly #response: AccessResponse;
  #closed = false;
  #binding: BrowserBinding | null;
  #enrollment: { handle: BrowserBinding | null; controller: AbortController; done: Promise<void> } | null = null;
  #logout: Promise<LogoutResult> | null = null;

  constructor(http: Http, response: AccessResponse, binding: BrowserBinding | null) {
    this.#http = http;
    this.#response = response;
    this.#binding = binding;
  }

  snapshot(): AccessSnapshot {
    const { scope, principal, expiresAt, environment, terminalAvailable } = this.#response;
    return Object.freeze({ scope, principal, expiresAt, environment, terminalAvailable });
  }
  toJSON(): AccessSnapshot { return this.snapshot(); }

  terminalToken(): string {
    if (this.#closed || !this.#response.terminalAvailable || Date.now() >= Date.parse(this.#response.expiresAt)) throw new RememberMeError('denied');
    return this.#response.accessToken; // Only the terminal wire adapter should consume this value.
  }

  async remember(options: { explicitOptIn: boolean }, signal?: AbortSignal): Promise<void> {
    if (options?.explicitOptIn !== true) throw new RememberMeError('opt-in-required');
    if (this.#closed) throw new RememberMeError('denied');
    if (this.#enrollment !== null) throw new RememberMeError('busy');
    if (this.#binding !== null) throw new RememberMeError(this.#binding.binding === null ? 'outcome-unknown' : 'already-remembered');
    const controller = new AbortController();
    const stopped = signal === undefined ? controller.signal : AbortSignal.any([controller.signal, signal]);
    const operation = { handle: null as BrowserBinding | null, controller, done: Promise.resolve() };
    this.#enrollment = operation;
    operation.done = this.#enroll(operation, stopped);
    try { await operation.done; }
    finally { if (this.#enrollment === operation) this.#enrollment = null; }
  }

  async #enroll(operation: { handle: BrowserBinding | null }, signal: AbortSignal): Promise<void> {
    let proving = false;
    try {
      if (signal.aborted) throw new RememberMeError('cancelled');
      if (await BrowserBinding.load(this.#response.scope) !== null) throw new RememberMeError('already-remembered');
      operation.handle = await BrowserBinding.prepare(this.#response.scope, { explicitOptIn: true });
      this.#binding = operation.handle; // Retain ownership even if the claim response is lost.
      if (signal.aborted) throw new RememberMeError('cancelled');
      const start = await startProof(this.#http, operation.handle, 'enroll', this.#response.accessToken, signal);
      const signature = await operation.handle.sign(start.challenge, 'enroll');
      if (signal.aborted) throw new RememberMeError('cancelled');
      proving = true; // Any subsequent failure may have committed a server binding.
      const response = object(await this.#http.post('remember/prove', { signature }, start.attemptToken, 201, signal), ['status', 'flow', 'sessionId', 'bindingId', 'expiresAt']);
      if (response.status !== 'remembered') throw new RememberMeError('unavailable');
      time(response.expiresAt);
      const binding: Binding = { flow: response.flow as string, sessionId: response.sessionId as string, bindingId: response.bindingId as string };
      validateBinding(binding);
      // sign() already checked this exact original challenge. Enrollment replies
      // must name its flow/session, not an unrelated selector from a response.
      const challenge = JSON.parse(new TextDecoder().decode(decode64(start.challenge, 16 << 10)).split('\0')[1]!) as Record<string, unknown>;
      if (challenge.flow !== binding.flow || challenge.sessionId !== binding.sessionId) throw new RememberMeError('unavailable');
      if (signal.aborted || this.#closed) throw new RememberMeError('cancelled');
      operation.handle = await operation.handle.complete(binding);
      this.#binding = operation.handle;
      if (signal.aborted || this.#closed) throw new RememberMeError('cancelled');
    } catch (error) {
      if (!proving && operation.handle !== null) {
        try {
          await operation.handle.forgetLocal();
          if (this.#binding === operation.handle) this.#binding = null;
        } catch { /* Preserve newer/corrupt state for explicit recovery, never overwrite it. */ }
      }
      if (proving) throw new RememberMeError('outcome-unknown'); // No replay/automatic logout or destructive rollback.
      throw error instanceof RememberMeError ? error : new RememberMeError('unavailable');
    }
  }

  // Stop new use immediately. Server logout is authoritative, including while
  // enrollment is signing/committing; parent closure prevents late enrollment.
  // On failure keep local keys/selectors for explicit retry, never claim logout.
  async logout(): Promise<LogoutResult> {
    if (this.#logout !== null) return this.#logout;
    this.#closed = true;
    const enrollment = this.#enrollment;
    enrollment?.controller.abort();
    const operation = (async () => {
      let failed: unknown;
      try { await this.#http.post('logout', {}, this.#response.accessToken, 204); }
      catch (error) { failed = error; }
      await enrollment?.done.catch(() => undefined);
      const handle = this.#binding ?? enrollment?.handle;
      if (failed !== undefined) {
        // A grant with no active children may already have been pruned. Prove
        // ownership of ONLY this access's own binding, never one loaded from a
        // different regular login/actor in this browser's IndexedDB.
        if (failed instanceof RememberMeError && failed.code === 'denied' && handle?.binding !== null && handle?.binding !== undefined) await revoke(this.#http, handle);
        else throw failed;
      }
      return forgetOwned(handle);
    })();
    this.#logout = operation;
    try { return await operation; }
    catch (error) { this.#logout = null; throw error; }
  }
}

export class BrowserClient {
  readonly #scope: Scope;
  readonly #http: Http;
  #loginActive = false;
  constructor(scope: Scope, transport?: Transport) {
    this.#http = new Http(scope, transport);
    this.#scope = Object.freeze({ ...scope });
  }

  async password(user: string, password: string, signal?: AbortSignal): Promise<WebAccess> {
    const encoder = new TextEncoder();
    if (typeof user !== 'string' || !user.isWellFormed() || encoder.encode(user).byteLength > 256 || /[\p{Cc}]/u.test(user) ||
        typeof password !== 'string' || !password.isWellFormed() || encoder.encode(password).byteLength > 4096) throw new RememberMeError('unavailable');
    const response = accessResponse(await this.#http.post('login/password', { user, password }, undefined, 200, signal), this.#scope);
    if (signal?.aborted) throw new RememberMeError('cancelled');
    return new WebAccess(this.#http, response, null);
  }

  async interactive(user: string, handler: StepHandler, signal?: AbortSignal): Promise<WebAccess> {
    if (this.#loginActive) throw new RememberMeError('busy');
    if (typeof user !== 'string' || !user.isWellFormed() || new TextEncoder().encode(user).byteLength > 256 || /[\p{Cc}]/u.test(user)) throw new RememberMeError('unavailable');
    this.#loginActive = true;
    try {
      const value = await interactive(this.#http, user, handler, signal);
      if (signal?.aborted) throw new RememberMeError('cancelled');
      try { return new WebAccess(this.#http, accessResponse(value, this.#scope), null); }
      catch { throw new RememberMeError('login-unknown'); }
    } finally { this.#loginActive = false; }
  }

  async publicKey(user: string, key: LoginKey, signal?: AbortSignal): Promise<WebAccess> {
    if (this.#loginActive) throw new RememberMeError('busy');
    if (typeof user !== 'string' || !user.isWellFormed() || new TextEncoder().encode(user).byteLength > 256 || /[\p{Cc}]/u.test(user)) throw new RememberMeError('unavailable');
    this.#loginActive = true;
    try {
      const value = await publicKeyLogin(this.#http, this.#scope, user, key, signal);
      if (signal?.aborted) throw new RememberMeError('cancelled');
      try { return new WebAccess(this.#http, accessResponse(value, this.#scope), null); }
      catch { throw new RememberMeError('login-unknown'); }
    } finally { this.#loginActive = false; }
  }

  async resume(signal?: AbortSignal): Promise<WebAccess | null> {
    if (signal?.aborted) throw new RememberMeError('cancelled');
    const handle = await BrowserBinding.load(this.#scope);
    if (handle === null) return null;
    if (handle.binding === null) throw new RememberMeError('outcome-unknown');
    const start = await startProof(this.#http, handle, 'resume', undefined, signal);
    const signature = await handle.sign(start.challenge, 'resume');
    const response = accessResponse(await this.#http.post('remember/prove', { signature }, start.attemptToken, 200, signal), this.#scope);
    if (signal?.aborted) throw new RememberMeError('cancelled');
    return new WebAccess(this.#http, response, handle);
  }

  async forgetRemembered(signal?: AbortSignal): Promise<LogoutResult> {
    const handle = await BrowserBinding.load(this.#scope);
    if (handle === null) return { localState: 'not-owned' };
    return this.revokeSelection(handle, signal);
  }

  // A confirmation dialog must retain the selected handle, not silently adopt
  // another tab's newer registration between showing the dialog and confirming.
  async revokeSelection(handle: BrowserBinding, signal?: AbortSignal): Promise<LogoutResult> {
    if (handle.scope.origin !== this.#scope.origin || handle.scope.slug !== this.#scope.slug) throw new RememberMeError('changed');
    await revoke(this.#http, handle, signal);
    return forgetOwned(handle); // CAS protects a newer enrollment in another tab.
  }
}
