import { expect, it } from 'vitest';
import type { LinkMetadata } from '../src/application/link-metadata';
import { allowsSavedLogin, loginChoiceFor } from '../src/login/choice';

const metadata: LinkMetadata = {
    scope: { origin: 'https://app.example.org', slug: 'Work' },
    rootAvailable: false,
    publishedSlugs: ['Work'],
    loginOptions: [
        {
            method: 'password',
            requestUser: true,
            certificateRequired: false,
            rememberMe: 'allowed',
        },
        {
            method: 'keyboard-interactive',
            requestUser: true,
            certificateRequired: false,
            rememberMe: 'allowed',
        },
        {
            method: 'public-key',
            requestUser: true,
            certificateRequired: false,
            rememberMe: 'allowed',
        },
    ],
};

it('defaults to Saved only for an available registration', () => {
    expect(loginChoiceFor(metadata, true, null)).toBe('saved');
    expect(loginChoiceFor(metadata, false, null)).toBe('password:named');
    expect(loginChoiceFor(metadata, false, 'saved')).toBe('password:named');
});

it('keeps an explicit primary choice when saved access becomes available', () => {
    for (const method of ['password:named', 'keyboard-interactive:named', 'public-key:named']) {
        expect(loginChoiceFor(metadata, true, method)).toBe(method);
    }
});

it('never offers a saved login forbidden by all configured options', () => {
    const forbidden: LinkMetadata = {
        ...metadata,
        loginOptions: metadata.loginOptions.map((option) => ({
            ...option,
            rememberMe: 'forbidden',
        })),
    };
    expect(allowsSavedLogin(forbidden)).toBe(false);
    expect(loginChoiceFor(forbidden, true, null)).toBe('password:named');
    expect(loginChoiceFor(forbidden, true, 'saved')).toBe('password:named');
    expect(loginChoiceFor({ ...metadata, loginOptions: [] }, true, null)).toBe('');
});
