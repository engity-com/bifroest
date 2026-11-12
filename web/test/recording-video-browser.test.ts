import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { page, userEvent } from 'vitest/browser';
import { PlaybackImage, type PlaybackOptions } from '../src/artifacts/playback-protocol';
import { fitPlaybackViewport } from '../src/artifacts/playback-view';
import { prepareRecordingPlayback } from '../src/artifacts/prepare-playback';
import { RecordingPlayer } from '../src/artifacts/RecordingPlayer';
import { t } from '../src/ui/messages';

vi.mock('../src/artifacts/prepare-playback', () => ({
    prepareRecordingPlayback: vi.fn(async (_source: Blob, expected: PlaybackOptions) =>
        fixture(expected),
    ),
}));
const cleanups: (() => void)[] = [];
function fixture(expected: PlaybackOptions) {
    const content = new TextEncoder().encode('\x1b]11;rgb:12/34/56\x07Recorded output\r\n');
    const resize = new Uint8Array(8);
    const dimensions = new DataView(resize.buffer);
    dimensions.setUint32(0, 132, true);
    dimensions.setUint32(4, 43, true);
    const frames = [
        { time: 0, kind: 0, data: content },
        { time: 10_000_000, kind: 3, data: resize },
    ];
    const bytes = new Uint8Array(
        frames.reduce((total, frame) => total + 13 + frame.data.length, 0),
    );
    const writer = new DataView(bytes.buffer);
    let at = 0;
    for (const frame of frames) {
        writer.setBigUint64(at, BigInt(frame.time), true);
        writer.setUint8(at + 8, frame.kind);
        writer.setUint32(at + 9, frame.data.length, true);
        bytes.set(frame.data, at + 13);
        at += 13 + frame.data.length;
    }
    return new PlaybackImage(
        expected,
        {
            version: 1,
            recordingId: expected.id,
            producer: expected.producer,
            trust: 'pinned',
            columns: 80,
            rows: 24,
            pty: true,
            frames: 2,
            durationUs: 30_000_000,
            status: 'completed',
            exitStatus: 0,
        },
        bytes.buffer,
    );
}
beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
    const nonce = document.createElement('meta');
    nonce.name = 'bifroest-nonce';
    nonce.content = `${'A'.repeat(43)}=`;
    document.head.append(nonce);
    cleanups.push(() => nonce.remove());
});
afterEach(async () => {
    await act(async () => {
        for (const cleanup of cleanups.splice(0)) {
            cleanup();
        }
    });
    vi.unstubAllGlobals();
});
async function mount(paneHeight?: number) {
    const container = document.createElement('div');
    container.style.width = '900px';
    container.style.maxWidth = '100%';
    if (paneHeight !== undefined) {
        container.dataset.playbackBounds = 'true';
        container.style.height = `${paneHeight}px`;
        container.style.overflow = 'auto';
    }
    document.body.append(container);
    const root = createRoot(container);
    cleanups.push(() => {
        root.unmount();
        container.remove();
    });
    await act(async () =>
        root.render(
            createElement(RecordingPlayer, {
                source: new Blob(['verified fixture']),
                expected: {
                    id: '34e34ab8-7457-4d88-a5e4-c57791775c3a',
                    producer: 'a'.repeat(64),
                    allowUntrusted: false,
                },
                disabled: false,
                autoPrepare: true,
            }),
        ),
    );
    await vi.waitFor(() =>
        expect(
            page
                .getByRole('button', { name: t('playbackPlay'), exact: true })
                .element()
                .hasAttribute('disabled'),
        ).toBe(false),
    );
    await vi.waitFor(() =>
        expect(document.querySelector<HTMLElement>('.playback-surface')?.style.transform).not.toBe(
            '',
        ),
    );
}
function verifyFit() {
    const stage = document.querySelector<HTMLElement>('.recording-video');
    const surface = document.querySelector<HTMLElement>('.playback-surface');
    const screen = surface?.querySelector<HTMLElement>('.xterm-screen');
    if (!stage || !surface || !screen) {
        throw new Error('Missing actual terminal geometry');
    }
    const box = stage.getBoundingClientRect();
    const shown = surface.getBoundingClientRect();
    const native = getComputedStyle(screen);
    const expected = fitPlaybackViewport(
        Number.parseFloat(native.width),
        Number.parseFloat(native.height),
        stage.clientWidth,
        stage.clientHeight,
    );
    expect(expected).not.toBeNull();
    expect(Math.abs(box.width / box.height - 16 / 9)).toBeLessThan(0.01);
    expect(shown.left).toBeGreaterThanOrEqual(box.left);
    expect(shown.top).toBeGreaterThanOrEqual(box.top);
    expect(shown.right).toBeLessThanOrEqual(box.right + 1);
    expect(shown.bottom).toBeLessThanOrEqual(box.bottom + 1);
    expect(
        Math.abs(
            shown.width -
                (shown.height * Number.parseFloat(native.width)) / Number.parseFloat(native.height),
        ),
    ).toBeLessThan(1);
    expect(Math.abs(shown.left - box.left - 1 - (expected?.left ?? 0))).toBeLessThan(1);
    return { stage, surface, screen };
}
describe('real console inside the recording video', () => {
    it('pauses running playback for help and closes without resuming or preparing another player', async () => {
        await page.viewport(1000, 800);
        await mount();
        const terminal = document.querySelector('.xterm-screen');
        const helpButton = page.getByRole('button', { name: t('playbackHelp'), exact: true });
        expect(helpButton.element().nextElementSibling).toBe(
            page.getByRole('button', { name: t('playbackFullscreen'), exact: true }).element(),
        );
        expect(prepareRecordingPlayback).toHaveBeenCalledOnce();
        await act(async () =>
            userEvent.click(page.getByRole('button', { name: t('playbackPlay'), exact: true })),
        );
        await vi.waitFor(() =>
            expect(
                document
                    .querySelector('[data-playback-phase]')
                    ?.getAttribute('data-playback-phase'),
            ).toBe('playing'),
        );
        await act(async () => userEvent.click(helpButton));
        const dialog = page.getByRole('dialog', { name: t('playbackHelp'), exact: true });
        await vi.waitFor(() => expect(dialog.element()).toBeDefined());
        expect(
            document.querySelector('[data-playback-phase]')?.getAttribute('data-playback-phase'),
        ).toBe('paused');
        expect(prepareRecordingPlayback).toHaveBeenCalledOnce();
        await act(async () =>
            userEvent.click(dialog.getByRole('button', { name: t('close'), exact: true })),
        );
        await vi.waitFor(() => expect(document.querySelector('[role="dialog"]')).toBeNull());
        expect(
            document.querySelector('[data-playback-phase]')?.getAttribute('data-playback-phase'),
        ).toBe('paused');
        expect(
            page
                .getByRole('button', { name: t('playbackPlay'), exact: true })
                .element()
                .hasAttribute('disabled'),
        ).toBe(false);
        expect(document.querySelector('.xterm-screen')).toBe(terminal);
        expect(prepareRecordingPlayback).toHaveBeenCalledOnce();
    });
    it('reduces both dimensions to fit a short viewing pane without stretching 16:9', async () => {
        await page.viewport(1400, 900);
        await mount(280);
        await vi.waitFor(() => {
            const { stage } = verifyFit();
            const bounds = stage.closest<HTMLElement>('[data-playback-bounds]');
            if (!bounds) {
                throw new Error('Missing viewing pane');
            }
            const box = stage.getBoundingClientRect();
            expect(box.height).toBeLessThan(280);
            expect(box.width).toBeLessThan(900);
            expect(box.bottom).toBeLessThanOrEqual(bounds.getBoundingClientRect().bottom + 1);
        });
    });
    it('enters native fullscreen with controls in the fullscreen element and restores 16:9 on exit', async () => {
        await page.viewport(1000, 800);
        await mount();
        const stage = document.querySelector<HTMLElement>('.recording-video');
        if (!stage) {
            throw new Error('Missing recording video');
        }
        await act(async () =>
            userEvent.click(
                page.getByRole('button', { name: t('playbackFullscreen'), exact: true }),
            ),
        );
        await vi.waitFor(() => expect(document.fullscreenElement).toBe(stage));
        await expect
            .element(page.getByRole('button', { name: t('playbackExitFullscreen'), exact: true }))
            .toBeVisible();
        await vi.waitFor(() => {
            expect(Math.abs(stage.getBoundingClientRect().width - window.innerWidth)).toBeLessThan(
                2,
            );
            expect(
                Math.abs(stage.getBoundingClientRect().height - window.innerHeight),
            ).toBeLessThan(2);
        });
        expect(
            stage.contains(
                page
                    .getByRole('button', { name: t('playbackExitFullscreen'), exact: true })
                    .element(),
            ),
        ).toBe(true);
        expect(
            stage.contains(
                page.getByRole('slider', { name: t('playbackSeek'), exact: true }).element(),
            ),
        ).toBe(true);
        await act(async () =>
            userEvent.click(page.getByRole('button', { name: t('playbackHelp'), exact: true })),
        );
        const help = page.getByRole('dialog', { name: t('playbackHelp'), exact: true });
        await vi.waitFor(() => expect(stage.contains(help.element())).toBe(true));
        expect(document.fullscreenElement).toBe(stage);
        await act(async () => userEvent.keyboard('{Escape}'));
        await vi.waitFor(() => expect(document.querySelector('[role="dialog"]')).toBeNull());
        expect(document.fullscreenElement).toBe(stage);
        await act(async () => userEvent.keyboard('{Escape}'));
        await vi.waitFor(() => expect(document.fullscreenElement).toBeNull());
        await vi.waitFor(() => verifyFit());
        await act(async () => userEvent.keyboard('f'));
        await vi.waitFor(() => expect(document.fullscreenElement).toBe(stage));
        // The native property changes before fullscreenchange has necessarily
        // reached React. Require its rendered acknowledgement before using it.
        await expect
            .element(page.getByRole('button', { name: t('playbackExitFullscreen'), exact: true }))
            .toBeVisible();
        await act(async () =>
            userEvent.click(
                page.getByRole('button', { name: t('playbackExitFullscreen'), exact: true }),
            ),
        );
        await vi.waitFor(() => expect(document.fullscreenElement).toBeNull());
    });
    it('letterboxes an actual xterm and preserves the outer aspect during recorded resizes and narrow layouts', async () => {
        await page.viewport(1000, 900);
        await mount();
        await vi.waitFor(() => verifyFit());
        const before = document.querySelector<HTMLElement>('.xterm-screen')?.style.width;
        await act(async () =>
            userEvent.click(page.getByRole('application', { name: t('playbackVideo') })),
        );
        await act(async () => userEvent.keyboard('k'));
        await act(async () => userEvent.keyboard('5'));
        await vi.waitFor(() =>
            expect(document.querySelector<HTMLElement>('.xterm-screen')?.style.width).not.toBe(
                before,
            ),
        );
        await vi.waitFor(() => verifyFit());
        await vi.waitFor(() =>
            expect(
                getComputedStyle(document.querySelector('.recording-video') as HTMLElement)
                    .backgroundColor,
            ).toBe('rgb(18, 52, 86)'),
        );
        await page.viewport(390, 800);
        await vi.waitFor(() => verifyFit());
        expect(document.querySelector('[data-playback-phase]')?.textContent).toContain('0:15');
    });
});
