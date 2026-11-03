import { act, createElement, StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EvidenceError } from '../src/artifacts/evidence-protocol';
import { RecordingPlayback } from '../src/artifacts/playback';
import { PlaybackImage, type PlaybackOptions } from '../src/artifacts/playback-protocol';
import { prepareRecordingPlayback } from '../src/artifacts/prepare-playback';
import { RecordingPlayer } from '../src/artifacts/RecordingPlayer';
import { t } from '../src/ui/messages';

const terminals = vi.hoisted(() => ({ opened: 0, disposed: 0 }));
vi.mock('@xterm/xterm', () => ({
  Terminal: class {
    options: Record<string, unknown>;
    textarea = document.createElement('textarea');
    parser = { registerOscHandler: () => ({ dispose() {} }) };
    constructor(options: Record<string, unknown>) {
      this.options = options;
    }
    open(container: HTMLElement) {
      terminals.opened++;
      container.append(this.textarea);
    }
    write(_bytes: Uint8Array, done: () => void) {
      done();
    }
    reset() {}
    resize() {}
    dispose() {
      terminals.disposed++;
      this.textarea.remove();
    }
  },
}));
vi.mock('../src/terminal/renderer', () => ({ installTerminalRenderer: () => ({ dispose() {} }) }));
vi.mock('../src/artifacts/prepare-playback', () => ({ prepareRecordingPlayback: vi.fn() }));
const expected: PlaybackOptions = {
  id: '34e34ab8-7457-4d88-a5e4-c57791775c3a',
  producer: 'a'.repeat(64),
  allowUntrusted: false,
};
const images: PlaybackImage[] = [];
function image(options = expected) {
  const value = new PlaybackImage(
    options,
    {
      version: 1,
      recordingId: options.id,
      producer: options.producer || 'a'.repeat(64),
      trust: options.allowUntrusted ? 'untrusted' : 'pinned',
      columns: 80,
      rows: 24,
      pty: false,
      frames: 0,
      durationUs: 0,
      status: 'completed',
      exitStatus: 0,
    },
    new ArrayBuffer(0),
  );
  vi.spyOn(value, 'dispose');
  images.push(value);
  return value;
}
const cleanups: (() => void)[] = [];
beforeEach(() => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  const nonce = document.createElement('meta');
  nonce.name = 'bifroest-nonce';
  nonce.content = `${'A'.repeat(43)}=`;
  document.head.append(nonce);
  cleanups.push(() => nonce.remove());
  terminals.opened = 0;
  terminals.disposed = 0;
  images.length = 0;
  vi.mocked(prepareRecordingPlayback).mockImplementation(async (_source, options) =>
    image(options),
  );
  vi.spyOn(RecordingPlayback.prototype, 'play');
});
afterEach(async () => {
  await act(async () => {
    for (const cleanup of cleanups.splice(0)) {
      cleanup();
    }
  });
  vi.restoreAllMocks();
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});
async function mount(strict = false) {
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  const source = new Blob(['immutable checked Cast']);
  const render = async (options: { source?: Blob; disabled?: boolean; active?: boolean } = {}) => {
    await act(async () => {
      const content = createElement(RecordingPlayer, {
        source,
        expected,
        disabled: false,
        autoPrepare: true,
        ...options,
      });
      root.render(strict ? createElement(StrictMode, null, content) : content);
    });
  };
  cleanups.push(() => {
    root.unmount();
    container.remove();
  });
  await render();
  return { render };
}
function button(name: string) {
  const element = [...document.querySelectorAll('button')].find(
    (node) => node.textContent === name,
  );
  if (!element) {
    throw new Error(`Missing button ${name}`);
  }
  return element;
}
async function click(element: HTMLElement) {
  await act(async () => element.click());
}
async function ready() {
  await vi.waitFor(() => expect(button(t('playbackPlay')).disabled).toBe(false));
}

describe('preparing a player as part of the explicit open-recording task', () => {
  it('prepares once and never autoplays under StrictMode effect replay', async () => {
    await mount(true);
    await ready();
    expect(prepareRecordingPlayback).toHaveBeenCalledTimes(1);
    expect(terminals.opened).toBe(1);
    expect(RecordingPlayback.prototype.play).not.toHaveBeenCalled();
  });
  it('prepares the immutable verified image once, but never starts playback automatically', async () => {
    const app = await mount();
    await ready();
    expect(prepareRecordingPlayback).toHaveBeenCalledExactlyOnceWith(
      expect.any(Blob),
      expected,
      expect.any(AbortSignal),
    );
    expect(terminals.opened).toBe(1);
    expect(RecordingPlayback.prototype.play).not.toHaveBeenCalled();
    expect(
      document.querySelector('[data-playback-phase]')?.getAttribute('data-playback-phase'),
    ).toBe('paused');
    await app.render({ active: false });
    await app.render({ active: true });
    expect(prepareRecordingPlayback).toHaveBeenCalledTimes(1);
    expect(terminals.disposed).toBe(0);
    await click(button(t('playbackPlay')));
    expect(RecordingPlayback.prototype.play).toHaveBeenCalledTimes(1);
    await vi.waitFor(() =>
      expect(
        document.querySelector('[data-playback-phase]')?.getAttribute('data-playback-phase'),
      ).toBe('ended'),
    );
  });
  it('does not replay preparation on a disabled/re-enabled boundary or after explicitly closing its local player', async () => {
    const app = await mount();
    await ready();
    await app.render({ disabled: true });
    await app.render({ disabled: false });
    expect(prepareRecordingPlayback).toHaveBeenCalledTimes(1);
    expect(terminals.disposed).toBe(1);
    await click(button(t('playbackPrepare')));
    await ready();
    expect(prepareRecordingPlayback).toHaveBeenCalledTimes(2);
    await click(button(t('playbackDiscard')));
    await app.render({ active: false });
    await app.render({ active: true });
    expect(prepareRecordingPlayback).toHaveBeenCalledTimes(2);
  });
  it('leaves a failed preparation failed until an explicit retry', async () => {
    vi.mocked(prepareRecordingPlayback).mockRejectedValueOnce(new EvidenceError('verification'));
    const app = await mount();
    await vi.waitFor(() =>
      expect(document.body.textContent).toContain(t('playbackVerificationFailed')),
    );
    await app.render({ active: false });
    await app.render({ active: true });
    expect(prepareRecordingPlayback).toHaveBeenCalledTimes(1);
    expect(terminals.opened).toBe(0);
    await click(button(t('playbackPrepare')));
    await ready();
    expect(prepareRecordingPlayback).toHaveBeenCalledTimes(2);
    expect(RecordingPlayback.prototype.play).not.toHaveBeenCalled();
  });
  it('disposes a late image instead of adopting it after the immutable source changed', async () => {
    let release!: (value: PlaybackImage) => void;
    vi.mocked(prepareRecordingPlayback).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    );
    const app = await mount();
    const signal = vi.mocked(prepareRecordingPlayback).mock.calls[0]?.[2];
    await app.render({ source: new Blob(['new immutable image']) });
    await ready();
    expect(signal?.aborted).toBe(true);
    const late = image();
    await act(async () => release(late));
    expect(late.dispose).toHaveBeenCalledOnce();
    expect(terminals.opened).toBe(1);
    expect(prepareRecordingPlayback).toHaveBeenCalledTimes(2);
    expect(RecordingPlayback.prototype.play).not.toHaveBeenCalled();
  });
});
