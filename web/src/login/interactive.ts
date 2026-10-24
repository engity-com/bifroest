import { Http, isToken, object, time } from '../remember/http';
import { RememberMeError } from '../remember/protocol';

export interface LoginStep {
  readonly sequence: string;
  readonly kind: 'info' | 'error' | 'prompt';
  readonly message: string;
  readonly echo: boolean;
}
export type StepHandler = (step: LoginStep, signal: AbortSignal) => Promise<string | void>;
interface KeyStep { readonly sequence: string; readonly kind: 'public-key'; readonly message: ''; readonly echo: false; readonly challenge: string; }
type Step = LoginStep | KeyStep;
type AttemptHandler = (step: Step, expiresAt: string, signal: AbortSignal) => Promise<string | void>;
interface Pending { readonly expiresAt: string; readonly pollAfterMillis: number; readonly step: Step | null; readonly token: string | null; }
const encoder = new TextEncoder();

function step(value: unknown, key: boolean): Step {
  try {
    if (key) {
      const body = object(value, ['sequence', 'kind', 'echo', 'challenge']);
      if (body.sequence !== '1' || body.kind !== 'public-key' || body.echo !== false || typeof body.challenge !== 'string' || body.challenge.length > 12 << 10) throw new RememberMeError('invalid-step');
      return Object.freeze({ sequence: '1', kind: 'public-key', message: '', echo: false, challenge: body.challenge });
    }
    const body = object(value, ['sequence', 'kind', 'echo', ...(value !== null && typeof value === 'object' && Object.hasOwn(value, 'message') ? ['message'] : [])]);
    if (typeof body.sequence !== 'string' || !/^(?:[1-9]|[12][0-9]|3[0-2])$/.test(body.sequence) ||
        !['info', 'error', 'prompt'].includes(body.kind as string) || typeof body.echo !== 'boolean' ||
        body.kind !== 'prompt' && body.echo || body.message !== undefined && typeof body.message !== 'string') throw new RememberMeError('invalid-step');
    const message = (body.message as string | undefined) ?? '';
    if (!message.isWellFormed() || encoder.encode(message).byteLength > 8 << 10) throw new RememberMeError('invalid-step');
    return Object.freeze({ sequence: body.sequence, kind: body.kind as LoginStep['kind'], message, echo: body.echo });
  } catch { throw new RememberMeError('invalid-step'); }
}

function pending(value: unknown, start: boolean, key: boolean): Pending {
  try {
    const body = object(value, ['status', 'expiresAt', 'pollAfterMillis', ...(start ? ['attemptToken'] : []), ...(value !== null && typeof value === 'object' && Object.hasOwn(value, 'step') ? ['step'] : [])]);
    if (body.status !== 'pending' || !Number.isInteger(body.pollAfterMillis) || (body.pollAfterMillis as number) < 250 || (body.pollAfterMillis as number) > 30_000 ||
        start && !isToken(body.attemptToken, 'bwl1.')) throw new RememberMeError('invalid-step');
    return { expiresAt: time(body.expiresAt), pollAfterMillis: body.pollAfterMillis as number, token: start ? body.attemptToken as string : null, step: body.step === undefined ? null : step(body.step, key) };
  } catch { throw new RememberMeError('invalid-step'); }
}

function wait(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const cleanup = () => { clearTimeout(timer); signal.removeEventListener('abort', aborted); };
    const aborted = () => { cleanup(); reject(new RememberMeError('cancelled')); };
    const timer = setTimeout(() => { cleanup(); resolve(); }, milliseconds);
    signal.addEventListener('abort', aborted, { once: true });
    if (signal.aborted) aborted();
  });
}

// A handler is retired on cancellation even if caller code ignores its signal.
// Its result is never reused for another step and no new handler is spawned.
function answer(handler: AttemptHandler, selected: Step, expiresAt: string, signal: AbortSignal): Promise<string | void> {
  return new Promise((resolve, reject) => {
    const aborted = () => { signal.removeEventListener('abort', aborted); reject(new RememberMeError('cancelled')); };
    signal.addEventListener('abort', aborted, { once: true });
    if (signal.aborted) { aborted(); return; }
    Promise.resolve().then(() => { if (signal.aborted) throw new RememberMeError('cancelled'); return handler(selected, expiresAt, signal); }).then(resolve, reject).finally(() => signal.removeEventListener('abort', aborted)).catch(() => undefined);
  });
}

// Poll is a one-time CLAIM when complete, not an idempotent read. Failures never
// replay poll/reply or imply logout/disposal. Tokens/answers remain in this tab.
export async function interactive(http: Http, user: string, handler: StepHandler, signal?: AbortSignal): Promise<unknown> {
  return loginAttempt(http, user, async (selected, _expiry, stopped) => {
    if (selected.kind === 'public-key') throw new RememberMeError('invalid-step');
    return handler(selected, stopped);
  }, signal);
}

// Internal common state machine. A key attempt accepts only one proof step and
// uses the server's two-minute cap, never an interactive credential fallback.
export async function loginAttempt(http: Http, user: string, handler: AttemptHandler, signal?: AbortSignal, publicKey?: string): Promise<unknown> {
  const key = publicKey !== undefined;
  const lifetime = AbortSignal.timeout((key ? 2 : 10) * 60_000);
  const stopped = signal === undefined ? lifetime : AbortSignal.any([signal, lifetime]);
  let token: string | null = null, claimed = false, proofAnswered = false, lastSequence = 0, messages = 0, lastPoll = -Infinity;
  try {
    const start = await http.post(key ? 'login/public-key' : 'login/interactive', key ? { user, publicKey } : { user }, undefined, 202, stopped);
    // Retain a valid control token even if the remaining response is malformed,
    // so best-effort cleanup need not wait for server idle expiry.
    if (start !== null && typeof start === 'object' && isToken((start as Record<string, unknown>).attemptToken, 'bwl1.')) token = (start as Record<string, unknown>).attemptToken as string;
    let current = pending(start, true, key);
    token = current.token;
    const expiry = current.expiresAt;
    if (token === null) throw new RememberMeError('invalid-step');
    const poll = async (): Promise<Pending | { authorized: unknown }> => {
      await wait(Math.max(0, Math.max(1250, current.pollAfterMillis) - (performance.now() - lastPoll)), stopped);
      lastPoll = performance.now();
      let value: unknown;
      try { value = await http.post('login/poll', {}, token!, 200, stopped); }
      catch (error) { if (stopped.aborted) throw new RememberMeError('cancelled'); if (error instanceof RememberMeError && (error.code === 'denied' || error.code === 'rate-limited')) throw error; throw new RememberMeError('login-unknown'); }
      if (value !== null && typeof value === 'object' && (value as Record<string, unknown>).status === 'authorized') {
        claimed = true;
        if (key && !proofAnswered) throw new RememberMeError('invalid-step');
        return { authorized: value };
      }
      const selected = pending(value, false, key);
      if (selected.expiresAt !== expiry) throw new RememberMeError('invalid-step');
      return selected;
    };
    while (true) {
      if (stopped.aborted) throw new RememberMeError('cancelled');
      const selected = current.step;
      if (selected !== null) {
        if (Number(selected.sequence) !== lastSequence + 1 || ++lastSequence > (key ? 1 : 32)) throw new RememberMeError('invalid-step');
        messages += encoder.encode(selected.message).byteLength;
        if (messages > 32 << 10) throw new RememberMeError('invalid-step');
        const stepController = new AbortController();
        const stepSignal = AbortSignal.any([stopped, stepController.signal]);
        let result: string | void;
        try {
          const response = answer(handler, selected, expiry, stepSignal).then(value => ({ answer: value }));
          while (true) {
            const tick = new AbortController();
            try {
              const next = await Promise.race([response, wait(15_000, AbortSignal.any([stepSignal, tick.signal])).then(() => ({ keepalive: true as const }))]);
              if ('answer' in next) { result = next.answer; break; }
              const keepalive = await poll();
              if ('authorized' in keepalive || JSON.stringify(keepalive.step) !== JSON.stringify(selected)) throw new RememberMeError('login-unknown');
            } finally { tick.abort(); }
          }
        } finally { stepController.abort(); }
        const fields: Record<string, string> = { sequence: selected.sequence };
        if (selected.kind === 'prompt') {
          if (typeof result !== 'string' || !result.isWellFormed() || encoder.encode(result).byteLength > 4096) throw new RememberMeError('invalid-step');
          fields.answer = result;
        } else if (selected.kind === 'public-key') {
          if (typeof result !== 'string' || result.length > 12 << 10) throw new RememberMeError('invalid-proof');
          fields.signature = result;
        } else if (result !== undefined && result !== '') throw new RememberMeError('invalid-step');
        try { current = pending(await http.post('login/reply', fields, token, 202, stopped), false, key); }
        catch (error) { if (stopped.aborted) throw new RememberMeError('cancelled'); if (error instanceof RememberMeError && error.code === 'rate-limited') throw error; throw new RememberMeError('login-unknown'); }
        if (selected.kind === 'public-key') proofAnswered = true;
        if (current.expiresAt !== expiry) throw new RememberMeError('invalid-step');
      } else {
        const next = await poll();
        if ('authorized' in next) return next.authorized;
        current = next;
      }
    }
  } catch (error) {
    if (stopped.aborted) throw new RememberMeError(signal?.aborted ? 'cancelled' : 'denied');
    throw error instanceof RememberMeError ? error : new RememberMeError('unavailable');
  } finally {
    if (token !== null && !claimed) {
      // Independent bounded cleanup is logical-attempt cancellation only. A lost
      // response is not retried and may already have consumed the claim.
      await http.post('login/cancel', {}, token, 204).catch(() => undefined);
    }
    token = null;
  }
}
