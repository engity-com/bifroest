import { afterEach, describe, expect, it, vi } from 'vitest';
import { BrowserClient } from '../src/remember';
import type { LoginStep } from '../src/remember';
import { verificationLink } from '../src/login/links';
import type { Transport } from '../src/remember/http';

const scope = { origin: 'https://app.example.org', slug: 'Work' };
const attemptToken = 'bwl1.' + 'A'.repeat(43);
const accessToken = 'bwa1.' + 'A'.repeat(43);
const info: LoginStep = { sequence: '1', kind: 'info', message: '<b>plain provider text</b>', echo: false };
function json(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }); }

class InteractiveServer {
  steps: LoginStep[] = [info, { sequence: '2', kind: 'error', message: 'warning', echo: false }, { sequence: '3', kind: 'prompt', message: 'Visible answer', echo: true }, { sequence: '4', kind: 'prompt', message: 'Secret answer', echo: false }];
  index = 0; cancelled = 0; polls = 0; replies = 0; claimed = false;
  expiry = new Date(Date.now() + 600_000).toISOString();
  requests: { action: string; fields: Record<string, string>; bearer: string | null; options: RequestInit }[] = [];
  transform: ((value: unknown) => unknown) | undefined;
  loseReply = false; losePoll = false;
  pending(start = false): unknown { return { status: 'pending', expiresAt: this.expiry, pollAfterMillis: 1000, ...(start ? { attemptToken } : {}), ...(this.steps[this.index] === undefined ? {} : { step: this.steps[this.index] }) }; }
  fetch: Transport = async (input, options) => {
    const action = new URL(String(input)).pathname.split('/api/v1/')[1]!;
    const fields = JSON.parse(options!.body as string) as Record<string, string>;
    const bearer = new Headers(options?.headers).get('Authorization')?.slice(7) ?? null;
    this.requests.push({ action, fields, bearer, options: options! });
    if (action === 'login/interactive') return json(this.transform?.(this.pending(true)) ?? this.pending(true), 202);
    if (bearer !== attemptToken) return json({}, 401);
    if (action === 'login/cancel') { this.cancelled++; return new Response(null, { status: 204 }); }
    if (action === 'login/reply') {
      this.replies++;
      if (this.steps[this.index]?.sequence !== fields.sequence) return json({}, 409);
      this.index++;
      if (this.loseReply) throw new Error('private dropped reply diagnostic');
      return json(this.transform?.(this.pending()) ?? this.pending(), 202);
    }
    if (action === 'login/poll') {
      this.polls++;
      if (this.index < this.steps.length) return json(this.pending());
      if (this.claimed) return json({}, 401);
      this.claimed = true;
      if (this.losePoll) throw new Error('private dropped claim diagnostic');
      return json({ status: 'authorized', accessToken, expiresAt: new Date(Date.now() + 600_000).toISOString(), scope, principal: 'verified-principal', environment: 'terminal', terminalAvailable: true });
    }
    return json({}, 404);
  };
  client() { return new BrowserClient(scope, this.fetch); }
}
afterEach(() => vi.useRealTimers());

describe('bounded interactive login and device-flow adapter', () => {
  it('acknowledges text, preserves prompt echo, sends each answer once and claims an opaque access', async () => {
    const server = new InteractiveServer(), seen: LoginStep[] = [];
    const access = await server.client().interactive('alice', async step => { seen.push(step); return step.kind === 'prompt' ? step.echo ? 'visible' : 'secret' : ''; });
    expect(seen.map(step => [step.sequence, step.kind, step.echo])).toEqual([['1', 'info', false], ['2', 'error', false], ['3', 'prompt', true], ['4', 'prompt', false]]);
    expect(seen[0]!.message).toBe('<b>plain provider text</b>'); expect(Object.isFrozen(seen[0])).toBe(true);
    expect(JSON.stringify(seen)).not.toContain('bwl1.');
    expect(server.replies).toBe(4); expect(server.polls).toBe(1); expect(server.cancelled).toBe(0);
    expect(access.snapshot().principal).toBe('verified-principal'); expect(JSON.stringify(access)).not.toContain(accessToken);
    for (const request of server.requests) {
      expect(request.options).toMatchObject({ credentials: 'omit', mode: 'same-origin', redirect: 'error', cache: 'no-store' });
      expect(request.fields.slug).toBe('Work');
      expect(Object.values(request.fields)).not.toContain(attemptToken);
    }
    expect(server.requests.filter(request => request.action === 'login/reply').map(request => request.fields)).toEqual([
      { slug: 'Work', sequence: '1' }, { slug: 'Work', sequence: '2' }, { slug: 'Work', sequence: '3', answer: 'visible' }, { slug: 'Work', sequence: '4', answer: 'secret' },
    ]);
  });

  it('does not replay a lost reply or final claim and never mistakes cancellation for logout', async () => {
    for (const kind of ['reply', 'poll']) {
      const server = new InteractiveServer();
      server.loseReply = kind === 'reply'; server.losePoll = kind === 'poll';
      await expect(server.client().interactive('', async step => step.kind === 'prompt' ? 'secret' : '')).rejects.toMatchObject({ code: 'login-unknown' });
      expect(server.cancelled).toBe(1); expect(server.requests.some(request => request.action === 'logout')).toBe(false);
      expect(kind === 'reply' ? server.replies : server.polls).toBe(1);
    }
  });

  it('rejects bad sequence/kind/echo/message fields before asking for a credential', async () => {
    for (const changed of [{ ...info, sequence: '0' }, { ...info, sequence: '01' }, { ...info, sequence: '33' }, { ...info, kind: 'public-key' }, { ...info, echo: true }, { ...info, challenge: 'unexpected' }, { ...info, message: 'x'.repeat(8193) }, { ...info, message: '\ud800' }]) {
      const server = new InteractiveServer(); server.transform = value => ({ ...value as object, step: changed });
      const handler = vi.fn(async () => 'must-not-be-used');
      await expect(server.client().interactive('alice', handler)).rejects.toMatchObject({ code: 'invalid-step' });
      expect(handler).not.toHaveBeenCalled(); expect(server.replies).toBe(0);
    }
    const skipped = new InteractiveServer(); skipped.steps = [{ ...info, sequence: '2' }];
    await expect(skipped.client().interactive('alice', async () => '')).rejects.toMatchObject({ code: 'invalid-step' });
    expect(skipped.cancelled).toBe(1);
  });

  it('rejects stale/repeated steps and never reuses a previous secret', async () => {
    const server = new InteractiveServer(); server.steps = [info, { ...info, sequence: '1', kind: 'prompt', message: 'repeat', echo: false }];
    const handler = vi.fn(async () => '');
    await expect(server.client().interactive('alice', handler)).rejects.toMatchObject({ code: 'invalid-step' });
    expect(handler).toHaveBeenCalledTimes(1); expect(server.replies).toBe(1); expect(server.cancelled).toBe(1);
  });

  it('bounds cumulative text and answers, including UTF-8 byte count', async () => {
    const large = new InteractiveServer(); large.steps = Array.from({ length: 5 }, (_, index) => ({ sequence: String(index + 1), kind: 'info', message: 'x'.repeat(8192), echo: false }));
    const handler = vi.fn(async () => '');
    await expect(large.client().interactive('alice', handler)).rejects.toMatchObject({ code: 'invalid-step' });
    expect(handler).toHaveBeenCalledTimes(4);
    const answer = new InteractiveServer(); answer.steps = [{ ...info, kind: 'prompt' }];
    await expect(answer.client().interactive('alice', async () => '€'.repeat(1400))).rejects.toMatchObject({ code: 'invalid-step' });
    expect(answer.replies).toBe(0); expect(answer.cancelled).toBe(1);
  });

  it('cancels an outstanding prompt without adopting a late handler result', async () => {
    const server = new InteractiveServer(), controller = new AbortController();
    let answer!: (value: string) => void;
    let entered!: () => void; const started = new Promise<void>(resolve => { entered = resolve; });
    const login = server.client().interactive('alice', async () => { entered(); return new Promise<string>(resolve => { answer = resolve; }); }, controller.signal);
    await started; controller.abort(); await expect(login).rejects.toMatchObject({ code: 'cancelled' });
    answer('late secret'); await Promise.resolve(); expect(server.replies).toBe(0); expect(server.cancelled).toBe(1);
  });

  it('keeps a long prompt alive without re-displaying it or duplicating its answer', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const server = new InteractiveServer(); server.steps = [{ ...info, kind: 'prompt' }];
    let resolve!: (value: string) => void;
    const handler = vi.fn(async () => new Promise<string>(done => { resolve = done; }));
    const login = server.client().interactive('alice', handler);
    await vi.advanceTimersByTimeAsync(15_001);
    expect(server.polls).toBe(1); expect(handler).toHaveBeenCalledTimes(1);
    resolve('secret'); await vi.advanceTimersByTimeAsync(1251);
    expect((await login).snapshot().principal).toBe('verified-principal'); expect(server.replies).toBe(1);
  });

  it('serializes logical interactive starts and does not emit new attempts while cleanup is active', async () => {
    const server = new InteractiveServer(), client = server.client(), controller = new AbortController();
    let entered!: () => void; const started = new Promise<void>(resolve => { entered = resolve; });
    const login = client.interactive('alice', async () => { entered(); return new Promise(() => {}); }, controller.signal);
    await started; await expect(client.interactive('bob', async () => '')).rejects.toMatchObject({ code: 'busy' });
    controller.abort(); await expect(login).rejects.toMatchObject({ code: 'cancelled' });
    expect(server.requests.filter(request => request.action === 'login/interactive')).toHaveLength(1);
  });
});

describe('provider link display policy', () => {
  it('offers explicit credential-free HTTPS only, never HTML/javascript/http links or automatic navigation', () => {
    expect(verificationLink('Code ABC. Visit https://identity.example/verify?code=ABC')).toBe('https://identity.example/verify?code=ABC');
    for (const text of ['<script>run()</script>', 'javascript:alert(1)', 'http://identity.example', 'https://user:secret@identity.example/verify', 'https://']) expect(verificationLink(text)).toBeNull();
  });
});
