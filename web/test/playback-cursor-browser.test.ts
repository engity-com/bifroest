import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, expect, it, vi } from 'vitest';
import { PlaybackImage, type PlaybackOptions } from '../src/artifacts/playback-protocol';
import { RecordingPlayer } from '../src/artifacts/RecordingPlayer';
import { t } from '../src/ui/messages';

// Exercise the supported DOM renderer deterministically; the same xterm options
// drive WebGL. Do not fake focus, private core services or cursor DOM classes.
vi.mock('../src/terminal/renderer', () => ({ installTerminalRenderer: () => ({ dispose() {} }) }));
vi.mock('../src/artifacts/prepare-playback', () => ({
  prepareRecordingPlayback: async (_source: Blob, options: PlaybackOptions) =>
    new PlaybackImage(
      options,
      {
        version: 1,
        recordingId: options.id,
        producer: options.producer,
        trust: 'pinned',
        columns: 80,
        rows: 24,
        pty: true,
        frames: 0,
        durationUs: 0,
        status: 'completed',
        exitStatus: 0,
      },
      new ArrayBuffer(0),
    ),
}));
const cleanups: (() => void)[] = [];
afterEach(async () => {
  await act(async () => {
    for (const cleanup of cleanups.splice(0)) {
      cleanup();
    }
  });
  vi.unstubAllGlobals();
});

it('renders a filled cursor before any player click, and keeps it filled after blur and reset', async () => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  const nonce = document.createElement('meta');
  nonce.name = 'bifroest-nonce';
  nonce.content = `${'A'.repeat(43)}=`;
  document.head.append(nonce);
  cleanups.push(() => nonce.remove());
  const outside = document.createElement('button');
  outside.textContent = 'Outside player';
  document.body.append(outside);
  outside.focus();
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  cleanups.push(() => {
    root.unmount();
    container.remove();
    outside.remove();
  });
  await act(async () =>
    root.render(
      createElement(RecordingPlayer, {
        source: new Blob(['checked fixture']),
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
  const filled = () => {
    expect(container.querySelector('.xterm-cursor-block')).not.toBeNull();
    expect(container.querySelector('.xterm-cursor-outline')).toBeNull();
  };
  await vi.waitFor(filled);
  expect(document.activeElement).toBe(outside);
  const input = container.querySelector<HTMLTextAreaElement>('.xterm-helper-textarea');
  if (!input) {
    throw new Error('Missing actual xterm textarea');
  }
  await act(async () => input.focus());
  await vi.waitFor(filled);
  await act(async () => outside.focus());
  await vi.waitFor(filled);
  const reset = [...container.querySelectorAll<HTMLButtonElement>('button')].find(
    (button) => button.getAttribute('aria-label') === t('playbackRestart'),
  );
  if (!reset) {
    throw new Error('Missing player reset');
  }
  await act(async () => reset.click());
  await vi.waitFor(filled);
  expect(document.activeElement).toBe(outside);
});
