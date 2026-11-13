import { act, createElement, useLayoutEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { expect, it, vi } from 'vitest';
import { verifyRecordingSource } from '../src/artifacts/recording-source-verification';
import { ArtifactSecretsBoundary } from '../src/artifacts/session-secrets';
import { useRecordingVerification } from '../src/artifacts/use-recording-verification';
import { WebAccess } from '../src/remember/client';
import { Http } from '../src/remember/http';

vi.mock('../src/artifacts/recording-source-verification', () => ({
    verifyRecordingSource: vi.fn(),
}));
type Verification = ReturnType<typeof useRecordingVerification>;
function Probe({
    access,
    source,
    changed,
}: {
    access: WebAccess;
    source: string;
    changed(value: Verification): void;
}) {
    const verification = useRecordingVerification({
        access,
        source,
        active: true,
        disabled: false,
    });
    useLayoutEffect(() => changed(verification));
    return null;
}

it('does not let a late former-source finally erase a new source private-view intent or clear its input state', async () => {
    vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
    const scope = { origin: 'https://app.example.org', slug: 'Original' };
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
            environment: 'management',
            terminalAvailable: false,
            accessToken: `bwa1.${'A'.repeat(43)}`,
        },
        null,
    );
    const old = Promise.withResolvers<Awaited<ReturnType<typeof verifyRecordingSource>>>();
    const next = Promise.withResolvers<Awaited<ReturnType<typeof verifyRecordingSource>>>();
    vi.mocked(verifyRecordingSource)
        .mockReturnValueOnce(old.promise)
        .mockReturnValueOnce(next.promise);
    const container = document.createElement('div');
    document.body.append(container);
    const root = createRoot(container);
    let latest: Verification | undefined;
    const current = () => {
        if (!latest) {
            throw new Error('Missing hook snapshot');
        }
        return latest;
    };
    const render = async (source: string) =>
        act(async () =>
            root.render(
                createElement(
                    ArtifactSecretsBoundary,
                    { access },
                    createElement(Probe, {
                        access,
                        source,
                        changed: (value) => {
                            latest = value;
                        },
                    }),
                ),
            ),
        );
    const completed = (source: string) => ({
        index: Object.freeze({ source, entries: [] }),
        result: {
            checked: 0,
            full: 0,
            outer: 0,
            producer: '',
            reported: true,
            metadataLimited: false,
        },
    });
    try {
        await render('First');
        await act(async () => current().dialogs.options.onStart());
        await vi.waitFor(() => expect(verifyRecordingSource).toHaveBeenCalledTimes(1));
        await render('Second');
        await act(async () => current().openPrivate());
        await act(async () => current().dialogs.options.onStart());
        await vi.waitFor(() => expect(verifyRecordingSource).toHaveBeenCalledTimes(2));
        const revision = current().dialogs.keyFields.revision;
        await act(async () => {
            old.resolve(completed('First'));
        });
        expect(current().dialogs.keyFields.revision).toBe(revision);
        expect(current().localIndex).toBeNull();
        expect(current().work.mode).toBe('cancel');
        const result = completed('Second');
        await act(async () => {
            next.resolve(result);
        });
        expect(current().localIndex).toBe(result.index);
        expect(current().revealIndex).toBe(result.index);
        expect(verifyRecordingSource).toHaveBeenCalledTimes(2);
    } finally {
        old.resolve(completed('First'));
        next.resolve(completed('Second'));
        await act(async () => root.unmount());
        container.remove();
        vi.restoreAllMocks();
        vi.unstubAllGlobals();
    }
});
