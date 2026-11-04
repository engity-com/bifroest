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
function image(options = expected, durationUs = 0) {
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
      durationUs,
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
    (node) => node.textContent === name || node.getAttribute('aria-label') === name,
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
  it('uses a fixed 16:9 stage with bottom controls rather than external playback buttons', async () => {
    await mount();
    await ready();
    const stage = document.querySelector<HTMLElement>('.recording-video');
    if (!stage) {
      throw new Error('Missing video stage');
    }
    expect(getComputedStyle(stage).aspectRatio).toBe('16 / 9');
    expect(stage.contains(button(t('playbackPlay')))).toBe(true);
    expect(stage.contains(document.querySelector('input[type="range"]'))).toBe(true);
    expect(document.querySelector('.recording-controls')?.tagName).toBe('FIELDSET');
    expect(
      getComputedStyle(document.querySelector('.recording-controls') as HTMLElement).bottom,
    ).toBe('0px');
  });

  it('handles focused keyboard shortcuts locally and does not hijack a speed selector', async () => {
    vi.mocked(prepareRecordingPlayback).mockImplementation(async (_source, options) =>
      image(options, 60_000_000),
    );
    const seeking = vi.spyOn(RecordingPlayback.prototype, 'seek');
    await mount();
    await ready();
    const stage = document.querySelector<HTMLElement>('.recording-video');
    if (!stage) {
      throw new Error('Missing video stage');
    }
    await act(async () =>
      stage.dispatchEvent(
        new KeyboardEvent('keydown', { key: ' ', bubbles: true, cancelable: true }),
      ),
    );
    expect(RecordingPlayback.prototype.play).toHaveBeenCalledOnce();
    await act(async () =>
      stage.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'k', bubbles: true, cancelable: true }),
      ),
    );
    await act(async () =>
      stage.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true, cancelable: true }),
      ),
    );
    expect(seeking).toHaveBeenCalledWith(expect.any(Number));
    expect(seeking.mock.calls.at(-1)?.[0]).toBeGreaterThanOrEqual(5_000_000);
    const selector = document.querySelector<HTMLSelectElement>('.recording-speed');
    if (!selector) {
      throw new Error('Missing speed control');
    }
    const before = seeking.mock.calls.length;
    await act(async () =>
      selector.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true, cancelable: true }),
      ),
    );
    expect(seeking).toHaveBeenCalledTimes(before);
    expect(prepareRecordingPlayback).toHaveBeenCalledOnce();
  });

  it('hides controls after playback inactivity and reveals them on pointer movement', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    vi.mocked(prepareRecordingPlayback).mockImplementation(async (_source, options) =>
      image(options, 60_000_000),
    );
    try {
      await mount();
      await ready();
      await click(button(t('playbackPlay')));
      const stage = document.querySelector<HTMLElement>('.recording-video');
      if (!stage) {
        throw new Error('Missing video stage');
      }
      await act(async () => vi.advanceTimersByTimeAsync(3001));
      expect(stage.dataset.controlsVisible).toBe('false');
      await act(async () =>
        stage.dispatchEvent(new PointerEvent('pointermove', { bubbles: true })),
      );
      expect(stage.dataset.controlsVisible).toBe('true');
      await click(button(t('playbackPause')));
      await act(async () => vi.advanceTimersByTimeAsync(4000));
      expect(stage.dataset.controlsVisible).toBe('true');
    } finally {
      vi.useRealTimers();
    }
  });

  it('uses native fullscreen state and cleans it up when the player is retired', async () => {
    let full: Element | null = null;
    Object.defineProperty(document, 'fullscreenElement', { configurable: true, get: () => full });
    const request = vi.spyOn(Element.prototype, 'requestFullscreen').mockImplementation(function (
      this: Element,
    ) {
      full = this;
      document.dispatchEvent(new Event('fullscreenchange'));
      return Promise.resolve();
    });
    const exit = vi.spyOn(document, 'exitFullscreen').mockImplementation(() => {
      full = null;
      document.dispatchEvent(new Event('fullscreenchange'));
      return Promise.resolve();
    });
    try {
      await mount();
      await ready();
      await click(button(t('playbackFullscreen')));
      expect(request).toHaveBeenCalledOnce();
      expect(full).toBe(document.querySelector('.recording-video'));
      expect(button(t('playbackExitFullscreen'))).toBeDefined();
      await click(button(t('playbackDiscard')));
      expect(exit).toHaveBeenCalledOnce();
      expect(full).toBeNull();
    } finally {
      Reflect.deleteProperty(document, 'fullscreenElement');
    }
  });

  it('keeps keyboard-focused controls and active scrubbing visible, and clears a cancelled preview', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    vi.mocked(prepareRecordingPlayback).mockImplementation(async (_source, options) =>
      image(options, 60_000_000),
    );
    vi.spyOn(Element.prototype, 'setPointerCapture').mockImplementation(() => {});
    try {
      await mount();
      await ready();
      await click(button(t('playbackPlay')));
      const stage = document.querySelector<HTMLElement>('.recording-video');
      const timeline = document.querySelector<HTMLInputElement>('.recording-timeline');
      if (!stage || !timeline) {
        throw new Error('Missing video controls');
      }
      await act(async () => {
        stage.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true }));
        timeline.focus();
      });
      await act(async () =>
        stage.dispatchEvent(new PointerEvent('pointermove', { bubbles: true })),
      );
      await act(async () => vi.advanceTimersByTimeAsync(3001));
      expect(stage.dataset.controlsVisible).toBe('true');
      await act(async () =>
        timeline.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true })),
      );
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      await act(async () => {
        setter?.call(timeline, '42000000');
        timeline.dispatchEvent(new Event('input', { bubbles: true }));
      });
      expect(timeline.value).toBe('42000000');
      await act(async () => vi.advanceTimersByTimeAsync(3001));
      expect(stage.dataset.controlsVisible).toBe('true');
      await act(async () =>
        timeline.dispatchEvent(new PointerEvent('pointercancel', { bubbles: true })),
      );
      expect(Number(timeline.value)).toBeLessThan(7_000_000);
      await act(async () => vi.advanceTimersByTimeAsync(3001));
      expect(stage.dataset.controlsVisible).toBe('false');
    } finally {
      vi.useRealTimers();
    }
  });

  it('reports denied fullscreen instead of pretending to be in fullscreen', async () => {
    vi.spyOn(Element.prototype, 'requestFullscreen').mockRejectedValue(new Error('denied'));
    await mount();
    await ready();
    await click(button(t('playbackFullscreen')));
    expect(document.body.textContent).toContain(t('playbackFullscreenFailed'));
    expect(button(t('playbackFullscreen'))).toBeDefined();
    expect(document.fullscreenElement).toBeNull();
  });

  it('exits a fullscreen request that completes after its player has been closed', async () => {
    let full: Element | null = null;
    let resolve!: () => void;
    Object.defineProperty(document, 'fullscreenElement', { configurable: true, get: () => full });
    vi.spyOn(Element.prototype, 'requestFullscreen').mockImplementation(function (this: Element) {
      return new Promise<void>((done) => {
        resolve = () => {
          full = this;
          done();
        };
      });
    });
    const exit = vi.spyOn(document, 'exitFullscreen').mockImplementation(() => {
      full = null;
      return Promise.resolve();
    });
    try {
      await mount();
      await ready();
      await click(button(t('playbackFullscreen')));
      await click(button(t('playbackDiscard')));
      await act(async () => resolve());
      expect(full).toBeNull();
      expect(exit).toHaveBeenCalledOnce();
      expect(prepareRecordingPlayback).toHaveBeenCalledOnce();
    } finally {
      Reflect.deleteProperty(document, 'fullscreenElement');
    }
  });

  it('binds media keys to explicit active-player ownership and releases them on tab deactivation', async () => {
    const handlers = new Map<MediaSessionAction, MediaSessionActionHandler | null>();
    const session = {
      metadata: null,
      playbackState: 'none',
      setPositionState: vi.fn(),
      setActionHandler: (action: MediaSessionAction, handler: MediaSessionActionHandler | null) => {
        handlers.set(action, handler);
      },
    };
    Object.defineProperty(navigator, 'mediaSession', { configurable: true, value: session });
    try {
      const first = await mount();
      await ready();
      expect(handlers.size).toBe(0);
      const firstStage = document.querySelector<HTMLElement>('.recording-video');
      if (!firstStage) {
        throw new Error('Missing first video');
      }
      await act(async () =>
        firstStage.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true })),
      );
      const previous = handlers.get('play');
      await mount();
      const secondStage = document.querySelectorAll<HTMLElement>('.recording-video')[1];
      if (!secondStage) {
        throw new Error('Missing second video');
      }
      await act(async () =>
        secondStage.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true })),
      );
      await act(async () => previous?.({ action: 'play' }));
      expect(RecordingPlayback.prototype.play).not.toHaveBeenCalled();
      await act(async () =>
        firstStage.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true })),
      );
      await act(async () => handlers.get('play')?.({ action: 'play' }));
      expect(RecordingPlayback.prototype.play).toHaveBeenCalledOnce();
      const owned = handlers.get('play');
      await first.render({ active: false });
      expect(handlers.get('play')).toBeNull();
      await act(async () => owned?.({ action: 'play' }));
      expect(RecordingPlayback.prototype.play).toHaveBeenCalledOnce();
      expect(prepareRecordingPlayback).toHaveBeenCalledTimes(2);
    } finally {
      Reflect.deleteProperty(navigator, 'mediaSession');
    }
  });

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
