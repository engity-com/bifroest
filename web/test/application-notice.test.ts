import { afterEach, expect, it, vi } from 'vitest';
import { RememberMeError } from '../src/remember/protocol';
import { errorNotice } from '../src/ui/ApplicationNotice';

afterEach(() => {
    vi.restoreAllMocks();
});

it('does not present keeping an existing registration as a notification or warning', () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(errorNotice(new RememberMeError('already-remembered'))).toBeNull();
    expect(log).not.toHaveBeenCalled();
});

it('still presents uncertain registration outcomes and real authentication failures', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(errorNotice(new RememberMeError('outcome-unknown'))).toMatchObject({ key: 'unknown' });
    expect(errorNotice(new RememberMeError('denied'))).toMatchObject({
        key: 'denied',
        color: 'red',
    });
});
