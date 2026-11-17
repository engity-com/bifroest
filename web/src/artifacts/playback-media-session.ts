import type { PlaybackState } from './playback';

interface MediaActions {
    play(): void;
    pause(): void;
    stop(): void;
    seek(positionUs: number): void;
    position(): number;
}
let owner: object | null = null;

// Best effort only: some browsers deliver hardware keys only for audio/video.
// Never create silent audio, upload content or expose recording/user metadata.
export function claimPlaybackMediaSession(actions: MediaActions, title: string) {
    const session = navigator.mediaSession;
    if (!session || typeof session.setActionHandler !== 'function') {
        return null;
    }
    const lease = {};
    owner = lease;
    const installed: MediaSessionAction[] = [];
    const handlers: Partial<Record<MediaSessionAction, MediaSessionActionHandler>> = {
        play: () => actions.play(),
        pause: () => actions.pause(),
        stop: () => actions.stop(),
        seekbackward: (details) =>
            actions.seek(actions.position() - (details.seekOffset ?? 10) * 1_000_000),
        seekforward: (details) =>
            actions.seek(actions.position() + (details.seekOffset ?? 10) * 1_000_000),
        seekto: (details) => {
            if (Number.isFinite(details.seekTime)) {
                actions.seek((details.seekTime ?? 0) * 1_000_000);
            }
        },
        previoustrack: () => actions.seek(0),
    };
    for (const [action, callback] of Object.entries(handlers)) {
        try {
            session.setActionHandler(action as MediaSessionAction, (details) => {
                if (owner === lease) {
                    callback(details);
                }
            });
            installed.push(action as MediaSessionAction);
        } catch {
            // Unsupported actions are optional and never change local playback state.
        }
    }
    try {
        if (typeof MediaMetadata === 'function') {
            session.metadata = new MediaMetadata({ title });
        }
    } catch {
        /* Optional browser API. */
    }
    return {
        update(state: PlaybackState, durationUs: number) {
            if (owner !== lease) {
                return;
            }
            try {
                session.playbackState = state.phase === 'playing' ? 'playing' : 'paused';
            } catch {
                /* Optional browser API. */
            }
            if (durationUs > 0 && typeof session.setPositionState === 'function') {
                try {
                    session.setPositionState({
                        duration: durationUs / 1_000_000,
                        playbackRate: state.speed,
                        position: Math.max(0, Math.min(durationUs, state.positionUs)) / 1_000_000,
                    });
                } catch {
                    // An unsupported/temporarily inactive OS media session is not a player failure.
                }
            }
        },
        dispose() {
            if (owner !== lease) {
                return;
            }
            owner = null;
            for (const action of installed) {
                try {
                    session.setActionHandler(action, null);
                } catch {
                    /* Optional browser API. */
                }
            }
            try {
                session.playbackState = 'none';
                session.metadata = null;
            } catch {
                /* Optional browser API. */
            }
            try {
                session.setPositionState?.();
            } catch {
                /* Optional browser API. */
            }
        },
    };
}
