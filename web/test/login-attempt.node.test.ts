import { expect, it, vi } from 'vitest';
import { LoginAttempt, type LoginSubmission } from '../src/login/attempt';
import type { StepHandler } from '../src/login/interactive';
import { WebAccess } from '../src/remember/client';
import { Http } from '../src/remember/http';
import { RememberMeError } from '../src/remember/protocol';

const scope = { origin: 'https://app.example.org', slug: 'Exact/Slug' };
const request = (): LoginSubmission => ({
    scope,
    method: 'password',
    user: 'Original',
    password: 'PRIVATE-PASSWORD',
    privateFile: null,
    certificateFile: null,
    passphrase: '',
    remember: false,
});
function fixture() {
    const access = new WebAccess(
        new Http(
            scope,
            vi.fn(async () => {
                throw new Error('Unexpected network');
            }),
        ),
        {
            scope,
            principal: 'Original',
            expiresAt: '2100-01-01T00:00:00Z',
            accessToken: `bwa1.${'A'.repeat(43)}`,
            environment: 'terminal',
            terminalAvailable: true,
        },
        null,
    );
    const client = {
        password: vi.fn(async () => access),
        interactive: vi.fn(
            async (_user: string, _handler: StepHandler, _signal?: AbortSignal) => access,
        ),
        publicKey: vi.fn(async () => access),
    };
    const attempt = new LoginAttempt();
    const signal = new AbortController().signal;
    const ports = { signal, current: () => true, admit: vi.fn(() => true) };
    return { access, client, attempt, ports };
}
it('executes only an explicit login and never stores credentials in the observable attempt state', async () => {
    const f = fixture();
    expect(f.client.password).not.toHaveBeenCalled();
    const completed = await f.attempt.start(f.client, request(), f.ports);
    expect(completed).toEqual({ kind: 'authorized', access: f.access, enrollment: 'none' });
    expect(f.client.password).toHaveBeenCalledExactlyOnceWith(
        'Original',
        'PRIVATE-PASSWORD',
        expect.any(AbortSignal),
    );
    expect(JSON.stringify(f.attempt.getSnapshot())).not.toContain('PRIVATE-PASSWORD');
});
it('pins an interactive answer to its exact current step and retires pending answers on cancellation', async () => {
    const f = fixture();
    const step = { sequence: '1', kind: 'prompt' as const, message: 'Question', echo: false };
    const answered = vi.fn();
    f.client.interactive.mockImplementation(async (_user, handler, signal) => {
        if (!signal) {
            throw new Error('Missing signal');
        }
        answered(await handler(step, signal));
        return f.access;
    });
    const pending = f.attempt.start(
        f.client,
        { ...request(), method: 'keyboard-interactive' },
        f.ports,
    );
    expect(f.attempt.getSnapshot().prompt).toBe(step);
    f.attempt.answer({ ...step }, 'wrong owner');
    expect(answered).not.toHaveBeenCalled();
    f.attempt.answer(step, 'PRIVATE-ANSWER');
    await pending;
    expect(answered).toHaveBeenCalledExactlyOnceWith('PRIVATE-ANSWER');
    expect(JSON.stringify(f.attempt.getSnapshot())).not.toContain('PRIVATE-ANSWER');
    const cancelled = f.attempt.start(
        f.client,
        { ...request(), method: 'keyboard-interactive' },
        f.ports,
    );
    const rejection = expect(cancelled).rejects.toMatchObject({ code: 'cancelled' });
    f.attempt.cancel();
    f.attempt.answer(step, 'late answer');
    await rejection;
    expect(f.attempt.getSnapshot().phase).toBe('cancelled');
});
it('never enrolls a route-mismatched access and never retries an uncertain enrollment', async () => {
    const f = fixture();
    const remember = vi
        .spyOn(f.access, 'remember')
        .mockRejectedValue(new RememberMeError('outcome-unknown'));
    f.ports.admit.mockReturnValueOnce(false);
    expect((await f.attempt.start(f.client, { ...request(), remember: true }, f.ports)).kind).toBe(
        'mismatch',
    );
    expect(remember).not.toHaveBeenCalled();
    const result = await f.attempt.start(f.client, { ...request(), remember: true }, f.ports);
    expect(result).toMatchObject({ kind: 'authorized', enrollment: 'unknown', access: f.access });
    expect(f.attempt.getSnapshot().phase).toBe('uncertain');
    expect(remember).toHaveBeenCalledOnce();
    expect(f.attempt.cancel()).toBe(true);
    await expect(f.attempt.start(f.client, request(), f.ports)).rejects.toMatchObject({
        code: 'outcome-unknown',
    });
    expect(f.client.password).toHaveBeenCalledTimes(2);
    f.attempt.retire();
    expect(f.attempt.getSnapshot().phase).toBe('idle');
});
it('preserves enrollment uncertainty when cancelled and discards its late completion', async () => {
    const f = fixture();
    const completion = Promise.withResolvers<void>();
    vi.spyOn(f.access, 'remember').mockReturnValue(completion.promise);
    const pending = f.attempt.start(f.client, { ...request(), remember: true }, f.ports);
    await vi.waitFor(() => expect(f.attempt.getSnapshot().phase).toBe('enrolling'));
    expect(f.attempt.cancel()).toBe(true);
    const rejection = expect(pending).rejects.toMatchObject({ code: 'cancelled' });
    completion.resolve();
    await rejection;
    expect(f.attempt.getSnapshot().phase).toBe('uncertain');
});
