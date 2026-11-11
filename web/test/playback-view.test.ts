import { afterEach, describe, expect, it, vi } from 'vitest';
import { claimPlaybackMediaSession } from '../src/artifacts/playback-media-session';
import { fitPlaybackViewport, playbackClock } from '../src/artifacts/playback-view';

afterEach(() => vi.unstubAllGlobals());
describe('fixed recording presentation', () => {
  it('fits without stretching, cropping, or changing the recorded terminal dimensions', () => {
    expect(fitPlaybackViewport(1600, 600, 1280, 720)).toEqual({ scale: 0.8, left: 0, top: 120 });
    expect(fitPlaybackViewport(600, 900, 1280, 720)).toEqual({ scale: 0.8, left: 400, top: 0 });
    expect(fitPlaybackViewport(1600, 900, 1920, 1080)).toEqual({ scale: 1.2, left: 0, top: 0 });
    expect(fitPlaybackViewport(800, 400, 400, 800)).toEqual({ scale: 0.5, left: 0, top: 300 });
    expect(fitPlaybackViewport(0, 600, 1280, 720)).toBeNull();
    expect(fitPlaybackViewport(800, 600, 0, 0)).toBeNull();
    expect(fitPlaybackViewport(Number.NaN, 600, 1280, 720)).toBeNull();
  });
  it('uses familiar video timestamps rather than raw fractional seconds', () => {
    expect(playbackClock(0)).toBe('0:00');
    expect(playbackClock(65_900_000)).toBe('1:05');
    expect(playbackClock(3_661_000_000)).toBe('1:01:01');
    expect(playbackClock(-1)).toBe('0:00');
    expect(playbackClock(Number.NaN)).toBe('0:00');
  });
});

function mediaFixture() {
  const handlers = new Map<MediaSessionAction, MediaSessionActionHandler | null>();
  const session = {
    metadata: null as unknown,
    playbackState: 'none',
    setActionHandler: vi.fn(
      (action: MediaSessionAction, handler: MediaSessionActionHandler | null) => {
        handlers.set(action, handler);
      },
    ),
    setPositionState: vi.fn(),
  };
  vi.stubGlobal('navigator', { mediaSession: session });
  vi.stubGlobal(
    'MediaMetadata',
    class {
      constructor(readonly value: unknown) {}
    },
  );
  return { session, handlers };
}
function actions() {
  return {
    play: vi.fn(),
    pause: vi.fn(),
    stop: vi.fn(),
    seek: vi.fn(),
    position: () => 20_000_000,
  };
}
describe('optional, owned OS media controls', () => {
  it('offers no fake media session when the browser API is absent', () => {
    vi.stubGlobal('navigator', {});
    expect(claimPlaybackMediaSession(actions(), 'Recording playback')).toBeNull();
  });
  it('routes hardware actions only to the latest explicit owner, without recording or account metadata', () => {
    const { session, handlers } = mediaFixture();
    const first = actions();
    const second = actions();
    const old = claimPlaybackMediaSession(first, 'Recording playback');
    const oldPlay = handlers.get('play');
    const current = claimPlaybackMediaSession(second, 'Recording playback');
    oldPlay?.({ action: 'play' });
    expect(first.play).not.toHaveBeenCalled();
    handlers.get('play')?.({ action: 'play' });
    expect(second.play).toHaveBeenCalledOnce();
    handlers.get('seekbackward')?.({ action: 'seekbackward', seekOffset: 5 });
    expect(second.seek).toHaveBeenLastCalledWith(15_000_000);
    handlers.get('seekto')?.({ action: 'seekto', seekTime: 42 });
    expect(second.seek).toHaveBeenLastCalledWith(42_000_000);
    current?.update({ phase: 'playing', positionUs: 12_000_000, speed: 2 }, 60_000_000);
    expect(session.setPositionState).toHaveBeenLastCalledWith({
      duration: 60,
      position: 12,
      playbackRate: 2,
    });
    expect(session.playbackState).toBe('playing');
    old?.dispose();
    expect(handlers.get('play')).not.toBeNull();
    expect(JSON.stringify(session.metadata)).toBe('{"value":{"title":"Recording playback"}}');
    current?.dispose();
    expect(handlers.get('play')).toBeNull();
    expect(session.playbackState).toBe('none');
  });
  it('does not turn unsupported OS media functions into playback failures', () => {
    const { session } = mediaFixture();
    session.setActionHandler.mockImplementation(() => {
      throw new Error('unsupported action');
    });
    session.setPositionState.mockImplementation(() => {
      throw new Error('unsupported position');
    });
    const current = claimPlaybackMediaSession(actions(), 'Recording playback');
    expect(() => current?.update({ phase: 'paused', positionUs: 0, speed: 1 }, 0)).not.toThrow();
    expect(() => current?.dispose()).not.toThrow();
  });
});
