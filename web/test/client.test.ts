import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BrowserBinding, BrowserClient, WebAccess } from '../src/remember';
import { decode64, encode64 } from '../src/remember/protocol';
import type { Binding, Scope } from '../src/remember';
import type { Transport } from '../src/remember/http';

const scope: Scope = { origin: 'https://app.example.org:8443', slug: 'Work' };
const flow = 'work';
const sessionId = '70d5159d-a0e4-46ca-b011-c4f831f4ade0';
function token(prefix: string): string { return prefix + encode64(crypto.getRandomValues(new Uint8Array(32))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''); }
function json(value: unknown, status = 200): Response { return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json; charset=utf-8' } }); }
function barrier(): { entered: Promise<void>; enter: () => void; released: Promise<void>; release: () => void } {
  let enter!: () => void, release!: () => void;
  return { entered: new Promise(resolve => { enter = resolve; }), get enter() { return enter; }, released: new Promise(resolve => { release = resolve; }), get release() { return release; } };
}

// Protocol fixture only; real Go HTTPS/authorizer integration is tested separately.
class Server {
  requests: { action: string; fields: Record<string, string>; bearer: string | null; options: RequestInit }[] = [];
  grants = new Map<string, { bindingId: string | null; closed: boolean; principal: string }>();
  bindings = new Map<string, { publicKey: string; principal: string }>();
  attempts = new Map<string, { challenge: Uint8Array<ArrayBuffer>; publicKey: string; purpose: string; grant?: string; binding?: string }>();
  failStart = false;
  failLogout = false;
  denyResume = false;
  beforeProof: (() => Promise<void>) | undefined;
  afterProof: ((response: Response) => Promise<Response>) | undefined;

  access(principal: string, bindingId: string | null = null): unknown {
    const accessToken = token('bwa1.');
    this.grants.set(accessToken, { principal, bindingId, closed: false });
    return { status: 'authorized', accessToken, expiresAt: new Date(Date.now() + 600_000).toISOString(), scope, principal, environment: 'terminal', terminalAvailable: true };
  }

  fetch: Transport = async (input, options) => {
    const action = new URL(String(input)).pathname.split('/api/v1/')[1]!;
    const fields = JSON.parse(options!.body as string) as Record<string, string>;
    const bearer = new Headers(options?.headers).get('Authorization')?.slice(7) ?? null;
    this.requests.push({ action, fields, bearer, options: options! });
    if (action === 'login/password') return fields.password === 'correct' ? json(this.access(fields.user!)) : json({}, 401);
    const grant = bearer === null ? undefined : this.grants.get(bearer);
    if (action === 'logout') {
      if (grant === undefined || grant.closed) return json({}, 401);
      grant.closed = true;
      if (this.failLogout) return json({ error: 'private storage diagnostic' }, 503);
      if (grant.bindingId !== null) this.revoke(grant.bindingId);
      return new Response(null, { status: 204 });
    }
    if (action !== 'remember/prove') {
      if (this.failStart) return json({}, 503);
      const purpose = action.split('/')[1]!;
      const binding = this.bindings.get(fields.bindingId!);
      if (purpose === 'enroll' ? grant === undefined || grant.closed || grant.bindingId !== null : binding === undefined || purpose === 'resume' && this.denyResume) return json({}, 401);
      const publicKey = purpose === 'enroll' ? fields.publicKey! : binding!.publicKey;
      const challenge = new TextEncoder().encode('bifroest-browser-remember-v1\0' + JSON.stringify({
        purpose, ...scope, flow, sessionId, bindingId: purpose === 'enroll' ? '' : fields.bindingId, revision: purpose === 'enroll' ? 0 : 1,
        target: 'f'.repeat(64), publicKey, nonce: encode64(crypto.getRandomValues(new Uint8Array(32))), expiresAt: new Date(Date.now() + 60_000).toISOString(),
      }));
      const attemptToken = token('bwr1.');
      this.attempts.set(attemptToken, { challenge, publicKey, purpose, ...(purpose === 'enroll' ? { grant: bearer! } : { binding: fields.bindingId! }) });
      return json({ status: 'proof-required', attemptToken, challenge: encode64(challenge), expiresAt: new Date(Date.now() + 60_000).toISOString() }, 202);
    }
    await this.beforeProof?.();
    const attempt = bearer === null ? undefined : this.attempts.get(bearer);
    if (attempt === undefined) return json({}, 401);
    this.attempts.delete(bearer!);
    const key = await crypto.subtle.importKey('raw', decode64(attempt.publicKey, 65), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, decode64(fields.signature!, 64), attempt.challenge)) return json({}, 401);
    let response: Response;
    if (attempt.purpose === 'enroll') {
      const primary = this.grants.get(attempt.grant!)!;
      if (primary.closed) return json({}, 401);
      const bindingId = token('bbr1.');
      this.bindings.set(bindingId, { publicKey: attempt.publicKey, principal: primary.principal });
      primary.bindingId = bindingId;
      response = json({ status: 'remembered', flow, sessionId, bindingId, expiresAt: new Date(Date.now() + 21_600_000).toISOString() }, 201);
    } else if (attempt.purpose === 'revoke') {
      this.revoke(attempt.binding!);
      response = new Response(null, { status: 204 });
    } else {
      const binding = this.bindings.get(attempt.binding!);
      if (binding === undefined) return json({}, 401);
      response = json(this.access(binding.principal, attempt.binding!));
    }
    return this.afterProof === undefined ? response : this.afterProof(response);
  };

  revoke(id: string): void {
    this.bindings.delete(id);
    for (const grant of this.grants.values()) if (grant.bindingId === id) grant.closed = true;
  }
  client(): BrowserClient { return new BrowserClient(scope, this.fetch); }
}

beforeEach(async () => {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase('bifroest-browser-remember-v1');
    request.onsuccess = () => resolve(); request.onerror = request.onblocked = () => reject(new Error('database blocked'));
  });
});

describe('browser HTTP RememberMe orchestration', () => {
  it('keeps primary grants only in opaque tab memory; no implicit enrollment', async () => {
    const server = new Server();
    const access = await server.client().password('alice', 'correct');
    expect(access).toBeInstanceOf(WebAccess);
    expect(access.snapshot().principal).toBe('alice');
    expect(JSON.stringify(access)).not.toContain('bwa1.');
    expect(access.terminalToken()).toMatch(/^bwa1\./);
    expect((await indexedDB.databases()).some(db => db.name === 'bifroest-browser-remember-v1')).toBe(false);
    await expect(access.remember({ explicitOptIn: false })).rejects.toMatchObject({ code: 'opt-in-required' });
    expect(server.requests).toHaveLength(1);
    expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0); expect(document.cookie).toBe('');
  });

  it('enrolls and resumes with actual signatures and strict cookie-free request options', async () => {
    const server = new Server(), client = server.client();
    const primary = await client.password('alice', 'correct');
    await primary.remember({ explicitOptIn: true });
    const handle = (await BrowserBinding.load(scope))!;
    expect(handle.binding?.bindingId).toBe([...server.bindings.keys()][0]);
    const resumed = (await client.resume())!;
    expect(resumed.snapshot().principal).toBe('alice');
    expect(resumed.terminalToken()).not.toBe(primary.terminalToken());
    expect(server.requests.map(request => request.action)).toEqual(['login/password', 'remember/enroll', 'remember/prove', 'remember/resume', 'remember/prove']);
    for (const request of server.requests) {
      expect(request.fields.slug).toBe('Work');
      expect(request.options).toMatchObject({ method: 'POST', credentials: 'omit', cache: 'no-store', mode: 'same-origin', redirect: 'error', referrerPolicy: 'no-referrer' });
      expect(new Headers(request.options.headers).has('Cookie')).toBe(false);
      expect(Object.values(request.fields).some(value => value.startsWith('bwa1.') || value.startsWith('bwr1.'))).toBe(false);
    }
    expect(server.requests[3]!.bearer).toBeNull();
    await resumed.logout();
    expect(await BrowserBinding.load(scope)).toBeNull();
    expect(server.bindings.size).toBe(0);
    expect(() => resumed.terminalToken()).toThrow();
  });

  it('does not revoke an existing actor binding when an unrelated regular login logs out', async () => {
    const server = new Server(), client = server.client();
    const alice = await client.password('alice', 'correct');
    await alice.remember({ explicitOptIn: true });
    const before = await BrowserBinding.load(scope);
    const bob = await client.password('bob', 'correct');
    await expect(bob.remember({ explicitOptIn: true })).rejects.toMatchObject({ code: 'already-remembered' });
    await bob.logout();
    expect(server.bindings.size).toBe(1);
    expect((await BrowserBinding.load(scope))?.binding).toEqual(before?.binding);
    expect(server.grants.get(alice.terminalToken())?.closed).toBe(false);
    expect(server.requests.some(request => request.action === 'remember/revoke')).toBe(false);
  });

  it('forgets only after durable proof revocation and retains keys on network failure', async () => {
    const server = new Server(), client = server.client();
    const access = await client.password('alice', 'correct');
    await access.remember({ explicitOptIn: true });
    server.failStart = true;
    await expect(client.forgetRemembered()).rejects.toMatchObject({ code: 'unavailable' });
    expect((await BrowserBinding.load(scope))?.binding).not.toBeNull();
    server.failStart = false;
    await client.forgetRemembered();
    expect(await BrowserBinding.load(scope)).toBeNull();
    expect(server.bindings.size).toBe(0);
    expect(server.requests.every(request => !request.action.includes('dispose'))).toBe(true);
  });

  it('cleans only its own pending state when enrollment never reaches proof', async () => {
    const server = new Server(), access = await server.client().password('alice', 'correct');
    server.failStart = true;
    await expect(access.remember({ explicitOptIn: true })).rejects.toMatchObject({ code: 'unavailable' });
    expect(await BrowserBinding.load(scope)).toBeNull();
    expect(server.bindings.size).toBe(0);
    expect(server.grants.get(access.terminalToken())?.closed).toBe(false);
  });

  it('retains ambiguous enrollment without retry or automatic logout; own logout reconciles it', async () => {
    const server = new Server(), client = server.client(), access = await client.password('alice', 'correct');
    server.afterProof = async () => { throw new Error('private lost-response diagnostic'); };
    await expect(access.remember({ explicitOptIn: true })).rejects.toMatchObject({ code: 'outcome-unknown', message: 'Browser RememberMe: outcome-unknown' });
    expect((await BrowserBinding.load(scope))?.binding).toBeNull();
    expect(server.bindings.size).toBe(1);
    expect(server.requests.filter(request => request.action === 'remember/prove')).toHaveLength(1);
    expect(server.requests.some(request => request.action === 'logout')).toBe(false);
    await expect(client.resume()).rejects.toMatchObject({ code: 'outcome-unknown' });
    await access.logout();
    expect(server.bindings.size).toBe(0);
    expect(await BrowserBinding.load(scope)).toBeNull();
  });

  it('preserves a committed server binding and pending keys if encrypted completion fails', async () => {
    const server = new Server(), access = await server.client().password('alice', 'correct');
    const failed = vi.spyOn(BrowserBinding.prototype, 'complete').mockRejectedValue(new Error('private browser quota diagnostic'));
    try { await expect(access.remember({ explicitOptIn: true })).rejects.toMatchObject({ code: 'outcome-unknown' }); }
    finally { failed.mockRestore(); }
    expect(server.bindings.size).toBe(1);
    expect((await BrowserBinding.load(scope))?.binding).toBeNull();
    await access.logout();
    expect(await BrowserBinding.load(scope)).toBeNull();
  });

  it('logout stops new local use and wins over a late enrollment claim', async () => {
    const server = new Server(), access = await server.client().password('alice', 'correct'), held = barrier();
    server.beforeProof = async () => { held.enter(); await held.released; };
    const enrollment = access.remember({ explicitOptIn: true }).catch(error => error as unknown);
    await held.entered;
    await expect(access.remember({ explicitOptIn: true })).rejects.toMatchObject({ code: 'busy' });
    const logout = access.logout();
    expect(() => access.terminalToken()).toThrow();
    held.release();
    expect(await enrollment).toMatchObject({ code: 'outcome-unknown' });
    await logout;
    expect(server.bindings.size).toBe(0);
    expect(await BrowserBinding.load(scope)).toBeNull();
  });

  it('does not revoke sibling grants or discard remembered state when a late resume is cancelled', async () => {
    const server = new Server(), client = server.client(), access = await client.password('alice', 'correct');
    await access.remember({ explicitOptIn: true });
    const held = barrier(), controller = new AbortController();
    server.afterProof = async response => { held.enter(); await held.released; return response; };
    const resumed = client.resume(controller.signal).catch(error => error as unknown);
    await held.entered; controller.abort(); held.release();
    expect(await resumed).toMatchObject({ code: 'cancelled' });
    expect(server.requests.some(request => request.action === 'logout' || request.action === 'remember/revoke')).toBe(false);
    expect(server.grants.get(access.terminalToken())?.closed).toBe(false);
    expect(server.bindings.size).toBe(1);
    expect((await BrowserBinding.load(scope))?.binding).not.toBeNull();
  });

  it('keeps key state after failed durable logout and retries with proof if the grant was pruned', async () => {
    const server = new Server(), access = await server.client().password('alice', 'correct');
    await access.remember({ explicitOptIn: true }); server.failLogout = true;
    await expect(access.logout()).rejects.toMatchObject({ code: 'unavailable' });
    expect(await BrowserBinding.load(scope)).not.toBeNull();
    expect(() => access.terminalToken()).toThrow();
    server.failLogout = false;
    await access.logout();
    expect(server.bindings.size).toBe(0);
    expect(await BrowserBinding.load(scope)).toBeNull();
    expect(server.requests.some(request => request.action === 'remember/revoke')).toBe(true);
  });

  it('requires regular login after expired eligibility without deleting keys or closing authenticated grants', async () => {
    const server = new Server(), client = server.client(), access = await client.password('alice', 'correct');
    await access.remember({ explicitOptIn: true }); server.denyResume = true;
    await expect(client.resume()).rejects.toMatchObject({ code: 'denied' });
    expect(server.grants.get(access.terminalToken())?.closed).toBe(false);
    expect(await BrowserBinding.load(scope)).not.toBeNull();
    const fresh = await client.password('alice', 'correct');
    expect(fresh.snapshot().principal).toBe('alice');
    expect(server.requests.some(request => request.action === 'logout' || request.action === 'remember/revoke')).toBe(false);
  });

  it('never stores another flow/session returned after a valid enrollment proof', async () => {
    const server = new Server(), access = await server.client().password('alice', 'correct');
    server.afterProof = async response => json({ ...await response.json() as object, sessionId: crypto.randomUUID() }, 201);
    await expect(access.remember({ explicitOptIn: true })).rejects.toMatchObject({ code: 'outcome-unknown' });
    expect((await BrowserBinding.load(scope))?.binding).toBeNull();
  });

  it('cannot delete a newer local registration after revoking its old binding', async () => {
    const server = new Server(), client = server.client(), access = await client.password('alice', 'correct');
    await access.remember({ explicitOptIn: true });
    const next: Binding = { flow, sessionId, bindingId: token('bbr1.') };
    server.afterProof = async response => {
      const old = (await BrowserBinding.load(scope))!; await old.forgetLocal();
      const newer = await BrowserBinding.prepare(scope, { explicitOptIn: true }); await newer.complete(next);
      return response;
    };
    await expect(client.forgetRemembered()).resolves.toEqual({ localState: 'changed' });
    expect((await BrowserBinding.load(scope))?.binding).toEqual(next);
  });

  it('revokes the confirmed selection, not another tab registration created while a dialog was open', async () => {
    const server = new Server(), client = server.client(), access = await client.password('alice', 'correct');
    await access.remember({ explicitOptIn: true });
    const selected = (await BrowserBinding.load(scope))!;
    await selected.forgetLocal();
    const next: Binding = { flow, sessionId, bindingId: token('bbr1.') };
    const replacement = await BrowserBinding.prepare(scope, { explicitOptIn: true }); await replacement.complete(next);
    await expect(client.revokeSelection(selected)).resolves.toEqual({ localState: 'changed' });
    expect(server.bindings.size).toBe(0);
    expect((await BrowserBinding.load(scope))?.binding).toEqual(next);
    const requests = server.requests.length;
    await expect(new BrowserClient({ ...scope, slug: 'Other' }, server.fetch).revokeSelection(selected)).rejects.toMatchObject({ code: 'changed' });
    expect(server.requests).toHaveLength(requests);
  });

  it('rejects oversized, foreign-scope and redirected grant responses without leaking diagnostics', async () => {
    for (const mode of ['oversized', 'scope', 'redirect', 'diagnostic']) {
      const server = new Server();
      const fetch: Transport = async () => {
        if (mode === 'oversized') return json({ text: 'private'.repeat(12_000) });
        if (mode === 'diagnostic') return json({ error: 'private upstream authentication diagnostic' }, 503);
        const response = json(mode === 'scope' ? { ...server.access('alice') as object, scope: { ...scope, slug: 'Other' } } : server.access('alice'));
        if (mode === 'redirect') Object.defineProperty(response, 'redirected', { value: true });
        return response;
      };
      await expect(new BrowserClient(scope, fetch).password('alice', 'correct')).rejects.toMatchObject({ code: 'unavailable', message: 'Browser RememberMe: unavailable' });
    }
  });
});
