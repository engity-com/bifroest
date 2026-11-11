import { type ReactNode, useRef } from 'react';
import { t } from '../ui/messages';
import type { PlaybackState } from './playback';
import { playbackClock, playbackSpeeds } from './playback-view';

function Icon({
    kind,
}: {
    kind: 'play' | 'pause' | 'restart' | 'fullscreen' | 'exit-fullscreen' | 'close' | 'help';
}) {
    const paths = {
        play: 'M8 5v14l11-7z',
        pause: 'M6 5h4v14H6zm8 0h4v14h-4z',
        restart: 'M12 5V1L7 6l5 5V7a6 6 0 1 1-6 6H4a8 8 0 1 0 8-8z',
        fullscreen: 'M5 5h5V3H3v7h2zm9-2v2h5v5h2V3zM5 14H3v7h7v-2H5zm14 5h-5v2h7v-7h-2z',
        'exit-fullscreen': 'M3 8v2h7V3H8v5zm11-5v7h7V8h-5V3zM8 21h2v-7H3v2h5zm6-7v7h2v-5h5v-2z',
        close: 'm6 4 6 6 6-6 2 2-6 6 6 6-2 2-6-6-6 6-2-2 6-6-6-6z',
        help: 'M11 18h2v-2h-2zm1-16a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm0 18a8 8 0 1 1 0-16 8 8 0 0 1 0 16zm0-14a4 4 0 0 0-4 4h2a2 2 0 1 1 3.4 1.4c-1 .8-2.4 1.6-2.4 3.6h2c0-1.3 1-1.8 1.8-2.6A4 4 0 0 0 12 6z',
    };
    return (
        <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d={paths[kind]} />
        </svg>
    );
}

export function PlaybackControls({
    state,
    durationUs,
    preview,
    disabled,
    fullscreen,
    canFullscreen,
    onToggle,
    onRestart,
    onSeek,
    onPreview,
    onScrub,
    onSpeed,
    onFullscreen,
    onHelp,
    onClose,
    verificationControls,
}: {
    state: PlaybackState | null;
    durationUs: number;
    preview: number | null;
    disabled: boolean;
    fullscreen: boolean;
    canFullscreen: boolean;
    onToggle(): void;
    onRestart(): void;
    onSeek(positionUs: number): void;
    onPreview(positionUs: number | null): void;
    onScrub(value: boolean): void;
    onSpeed(value: number): void;
    onFullscreen(): void;
    onHelp(): void;
    onClose(): void;
    verificationControls?: ReactNode;
}) {
    const pointer = useRef(false);
    const playing = state?.phase === 'playing';
    const seeking = state?.phase === 'seeking' || state?.phase === 'resetting';
    const position = Math.max(0, Math.min(durationUs, preview ?? state?.positionUs ?? 0));
    const playLabel = t(
        playing ? 'playbackPause' : state?.phase === 'ended' ? 'playbackReplay' : 'playbackPlay',
    );
    return (
        <fieldset className="recording-controls" aria-label={t('playbackControls')}>
            <input
                className="recording-timeline"
                type="range"
                min={0}
                max={Math.max(durationUs, 1)}
                step={1}
                value={position}
                aria-label={t('playbackSeek')}
                aria-valuetext={`${playbackClock(position)} / ${playbackClock(durationUs)}`}
                disabled={disabled || durationUs === 0}
                onPointerDown={(event) => {
                    pointer.current = true;
                    onScrub(true);
                    event.currentTarget.setPointerCapture?.(event.pointerId);
                }}
                onChange={(event) => {
                    const value = Number(event.currentTarget.value);
                    onPreview(value);
                    if (!pointer.current) {
                        onSeek(value);
                    }
                }}
                onPointerUp={(event) => {
                    pointer.current = false;
                    onScrub(false);
                    onSeek(Number(event.currentTarget.value));
                }}
                onPointerCancel={() => {
                    pointer.current = false;
                    onScrub(false);
                    onPreview(null);
                }}
                onLostPointerCapture={() => {
                    if (pointer.current) {
                        pointer.current = false;
                        onScrub(false);
                        onPreview(null);
                    }
                }}
                onKeyDown={(event) => {
                    if (event.key === ' ') {
                        event.preventDefault();
                        if (!event.repeat) {
                            onToggle();
                        }
                    } else {
                        const keys: Record<string, number> = {
                            ArrowLeft: position - 1_000_000,
                            ArrowDown: position - 1_000_000,
                            ArrowRight: position + 1_000_000,
                            ArrowUp: position + 1_000_000,
                            PageDown: position - 10_000_000,
                            PageUp: position + 10_000_000,
                            Home: 0,
                            End: durationUs,
                        };
                        const destination = keys[event.key];
                        if (destination !== undefined) {
                            event.preventDefault();
                            onSeek(Math.max(0, Math.min(durationUs, destination)));
                        }
                    }
                }}
            />
            <div className="recording-control-row">
                {verificationControls}
                <button
                    type="button"
                    className="recording-control"
                    aria-label={playLabel}
                    title={`${playLabel} (Space / K)`}
                    aria-keyshortcuts="Space K"
                    disabled={disabled || seeking}
                    onClick={onToggle}
                >
                    <Icon kind={playing ? 'pause' : 'play'} />
                </button>
                <button
                    type="button"
                    className="recording-control"
                    aria-label={t('playbackRestart')}
                    title={t('playbackRestart')}
                    disabled={disabled || seeking}
                    onClick={onRestart}
                >
                    <Icon kind="restart" />
                </button>
                <span className="recording-time" aria-hidden="true">
                    {playbackClock(position)} / {playbackClock(durationUs)}
                </span>
                <select
                    className="recording-speed"
                    aria-label={t('playbackSpeed')}
                    title={t('playbackSpeed')}
                    value={state?.speed ?? 1}
                    disabled={disabled || seeking}
                    onChange={(event) => onSpeed(Number(event.currentTarget.value))}
                >
                    {playbackSpeeds.map((value) => (
                        <option key={value} value={value}>
                            {value}×
                        </option>
                    ))}
                </select>
                <button
                    type="button"
                    className="recording-control"
                    aria-label={t('playbackHelp')}
                    title={t('playbackHelp')}
                    disabled={disabled || state === null}
                    onClick={onHelp}
                >
                    <Icon kind="help" />
                </button>
                <button
                    type="button"
                    className="recording-control"
                    aria-label={t(fullscreen ? 'playbackExitFullscreen' : 'playbackFullscreen')}
                    title={`${t(fullscreen ? 'playbackExitFullscreen' : 'playbackFullscreen')} (F)`}
                    aria-keyshortcuts="F"
                    disabled={disabled || !canFullscreen}
                    onClick={onFullscreen}
                >
                    <Icon kind={fullscreen ? 'exit-fullscreen' : 'fullscreen'} />
                </button>
                <button
                    type="button"
                    className="recording-control"
                    aria-label={t('playbackDiscard')}
                    title={t('playbackDiscard')}
                    disabled={disabled}
                    onClick={onClose}
                >
                    <Icon kind="close" />
                </button>
            </div>
        </fieldset>
    );
}
