import CancelIcon from '@mui/icons-material/Cancel';
import { Dialog, DialogActions, DialogContent, DialogTitle, IconButton } from '@mui/material';
import type { IDisposable, Terminal as Xterm } from '@xterm/xterm';
import {
  type KeyboardEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
} from 'react';
import { Alert, Button, useComputedColorScheme } from '../ui/material';
import { ReadProgress } from '../ui/ReadProgress';
import '@xterm/xterm/css/xterm.css';
import { noncedDocument } from '../terminal/document';
import { installTerminalRenderer } from '../terminal/renderer';
import { reportUiError } from '../ui/error-report';
import { t } from '../ui/messages';
import { EvidenceError } from './evidence-protocol';
import { PlaybackControls } from './PlaybackControls';
import type { PlaybackState } from './playback';
import { RecordingPlayback } from './playback';
import { initializePlaybackCursor } from './playback-cursor';
import { observePlaybackLayout } from './playback-layout';
import { claimPlaybackMediaSession } from './playback-media-session';
import type { PlaybackMetadata, PlaybackOptions } from './playback-protocol';
import { observePlaybackStage } from './playback-stage';
import { playbackClock, playbackSpeeds } from './playback-view';
import { prepareRecordingPlayback } from './prepare-playback';
import './recording-player.css';

export function RecordingPlayer({
  source,
  expected,
  disabled,
  autoPrepare = false,
  active = true,
  verificationControls,
  preparedImage,
  onPrepare,
}: {
  source: Blob;
  expected: PlaybackOptions;
  disabled: boolean;
  autoPrepare?: boolean;
  active?: boolean;
  verificationControls?: ReactNode;
  preparedImage?: import('./playback-protocol').PlaybackImage;
  onPrepare?: () => void;
}) {
  const container = useRef<HTMLElement | null>(null);
  const playerSection = useRef<HTMLElement | null>(null);
  const video = useRef<HTMLDivElement | null>(null);
  const toolbar = useRef<HTMLDivElement | null>(null);
  const preparing = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const emulator = useRef<Xterm | null>(null);
  const player = useRef<RecordingPlayback | null>(null);
  const subscriptions = useRef<IDisposable[]>([]);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<'limit' | 'verification' | 'unavailable' | null>(null);
  const [metadata, setMetadata] = useState<PlaybackMetadata | null>(null);
  const [state, setState] = useState<PlaybackState | null>(null);
  const stateNow = useRef<PlaybackState | null>(null);
  const disabledNow = useRef(disabled);
  disabledNow.current = disabled;
  const [preview, setPreview] = useState<number | null>(null);
  const seekingIntent = useRef(0);
  const playbackIntent = useRef(0);
  const [controlsVisible, setControlsVisible] = useState(true);
  const hideTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const keyboard = useRef(false);
  const scrubbing = useRef(false);
  const [fullscreen, setFullscreen] = useState(false);
  const [fullscreenFailed, setFullscreenFailed] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [mediaClaimed, setMediaClaimed] = useState(0);
  const helpID = useId();
  const fullscreenIntent = useRef(0);
  const media = useRef<ReturnType<typeof claimPlaybackMediaSession>>(null);
  const palette = useComputedColorScheme('light');
  const currentPalette = useRef(palette);
  currentPalette.current = palette;
  const activeNow = useRef(active);
  activeNow.current = active;
  const automaticAttempt = useRef(false);
  const automaticAllowed = useRef(autoPrepare && active && !disabled);
  automaticAllowed.current = autoPrepare && active && !disabled;
  const { id, producer, allowUntrusted } = expected;

  const reveal = useCallback((byKeyboard = keyboard.current) => {
    keyboard.current = byKeyboard;
    setControlsVisible(true);
    clearTimeout(hideTimer.current);
    hideTimer.current = setTimeout(() => {
      const focused = document.activeElement;
      const focusedControl = focused !== null && toolbar.current?.contains(focused);
      if (
        stateNow.current?.phase === 'playing' &&
        !scrubbing.current &&
        !(focusedControl && (keyboard.current || focused instanceof HTMLSelectElement))
      ) {
        setControlsVisible(false);
      }
    }, 3000);
  }, []);

  const canOperate = () => activeNow.current && !disabledNow.current && player.current !== null;
  const claimMedia = () => {
    if (canOperate() && document.visibilityState !== 'hidden') {
      // A fresh explicit interaction can reclaim ownership from another player.
      setMediaClaimed((claim) => claim + 1);
    }
  };
  const play = () => {
    const selected = player.current;
    if (!canOperate() || selected === null) {
      return;
    }
    claimMedia();
    const intent = ++playbackIntent.current;
    if (stateNow.current?.phase === 'ended') {
      void selected.restart().then(() => {
        if (player.current === selected && canOperate() && intent === playbackIntent.current) {
          selected.play();
        }
      });
    } else {
      selected.play();
    }
    reveal(keyboard.current);
  };
  const pause = () => {
    if (canOperate()) {
      claimMedia();
      playbackIntent.current++;
      player.current?.pause();
      reveal(keyboard.current);
    }
  };
  const toggle = () => {
    if (stateNow.current?.phase === 'playing') {
      pause();
    } else {
      play();
    }
  };
  const seek = (positionUs: number) => {
    const selected = player.current;
    if (!canOperate() || selected === null || !Number.isFinite(positionUs)) {
      return;
    }
    const target = Math.max(0, Math.min(metadata?.durationUs ?? 0, positionUs));
    const intent = ++seekingIntent.current;
    playbackIntent.current++;
    claimMedia();
    setPreview(target);
    reveal(keyboard.current);
    void selected.seek(target).then(() => {
      if (player.current === selected && intent === seekingIntent.current) {
        setPreview(null);
      }
    });
  };
  const changeSpeed = (value: number) => {
    if (canOperate()) {
      player.current?.speed(value);
      reveal(keyboard.current);
    }
  };
  const restart = () => {
    if (canOperate()) {
      claimMedia();
      playbackIntent.current++;
      reveal(keyboard.current);
      void player.current?.restart();
    }
  };
  const actions = useRef({ play, pause, seek, restart });
  actions.current = { play, pause, seek, restart };

  const toggleFullscreen = () => {
    const box = video.current;
    if (box === null) {
      return;
    }
    setFullscreenFailed(false);
    reveal(keyboard.current);
    const entering = document.fullscreenElement !== box;
    if (entering && typeof box.requestFullscreen !== 'function') {
      setFullscreenFailed(true);
      return;
    }
    const intent = ++fullscreenIntent.current;
    const sourceGeneration = generation.current;
    const operation = entering ? box.requestFullscreen() : document.exitFullscreen();
    void operation
      .then(() => {
        if (
          entering &&
          document.fullscreenElement === box &&
          (intent !== fullscreenIntent.current ||
            sourceGeneration !== generation.current ||
            !activeNow.current)
        ) {
          return document.exitFullscreen();
        }
      })
      .catch(() => {
        if (
          intent === fullscreenIntent.current &&
          sourceGeneration === generation.current &&
          video.current === box
        ) {
          setFullscreenFailed(true);
        }
      });
  };
  useEffect(() => {
    const changed = () => {
      setFullscreen(video.current !== null && document.fullscreenElement === video.current);
      reveal();
    };
    document.addEventListener('fullscreenchange', changed);
    return () => document.removeEventListener('fullscreenchange', changed);
  }, [reveal]);
  useEffect(() => () => clearTimeout(hideTimer.current), []);
  useEffect(() => {
    if (playerSection.current && video.current) {
      const stage = observePlaybackStage(playerSection.current, video.current);
      return () => stage.dispose();
    }
  }, []);
  useEffect(() => {
    if (state?.phase !== 'playing') {
      setControlsVisible(true);
    } else {
      reveal(keyboard.current);
    }
  }, [state?.phase, reveal]);
  useEffect(() => {
    if (!active) {
      setHelpOpen(false);
      playbackIntent.current++;
      player.current?.pause();
      setMediaClaimed(0);
      fullscreenIntent.current++;
      if (video.current !== null && document.fullscreenElement === video.current) {
        void document.exitFullscreen().catch(() => {});
      }
    }
  }, [active]);
  useEffect(() => {
    if (!mediaClaimed || !active || disabled || metadata === null) {
      return;
    }
    const claimed = claimPlaybackMediaSession(
      {
        play: () => actions.current.play(),
        pause: () => actions.current.pause(),
        stop: () => actions.current.restart(),
        seek: (position) => actions.current.seek(position),
        position: () => stateNow.current?.positionUs ?? 0,
      },
      t('playbackTitle'),
    );
    media.current = claimed;
    if (stateNow.current) {
      claimed?.update(stateNow.current, metadata.durationUs);
    }
    return () => {
      claimed?.dispose();
      if (media.current === claimed) {
        media.current = null;
      }
    };
  }, [mediaClaimed, active, disabled, metadata]);
  useEffect(() => {
    if (state && metadata) {
      media.current?.update(state, metadata.durationUs);
    }
  }, [state, metadata]);

  const handleKey = (event: KeyboardEvent<HTMLDivElement>) => {
    if (helpOpen) {
      return;
    }
    if (event.ctrlKey || event.metaKey || event.altKey) {
      return;
    }
    // Real browser chrome normally consumes Escape. Some embedded/headless
    // hosts deliver it to the page instead; exit the same native fullscreen.
    if (
      event.key === 'Escape' &&
      video.current !== null &&
      document.fullscreenElement === video.current
    ) {
      event.preventDefault();
      toggleFullscreen();
      return;
    }
    if (!canOperate()) {
      return;
    }
    reveal(true);
    claimMedia();
    const target = event.target as HTMLElement;
    const key = event.key.toLowerCase();
    if (
      target.closest('input,select,textarea,[contenteditable="true"]') &&
      !target.closest('.playback-surface') &&
      key !== 'mediaplaypause'
    ) {
      return;
    }
    if (target.closest('button') && (key === ' ' || key === 'enter')) {
      return;
    }
    const at = preview ?? stateNow.current?.positionUs ?? 0;
    if (key === ' ' || key === 'k' || key === 'mediaplaypause') {
      event.preventDefault();
      if (!event.repeat) {
        toggle();
      }
    } else if (key === 'arrowleft' || key === 'j') {
      event.preventDefault();
      seek(at - (key === 'j' ? 10 : 5) * 1_000_000);
    } else if (key === 'arrowright' || key === 'l') {
      event.preventDefault();
      seek(at + (key === 'l' ? 10 : 5) * 1_000_000);
    } else if (key === 'home' || key === '0') {
      event.preventDefault();
      seek(0);
    } else if (key === 'end') {
      event.preventDefault();
      seek(metadata?.durationUs ?? 0);
    } else if (/^[1-9]$/u.test(key)) {
      event.preventDefault();
      seek(((metadata?.durationUs ?? 0) * Number(key)) / 10);
    } else if (key === 'f') {
      event.preventDefault();
      toggleFullscreen();
    } else if (key === '<' || key === '>') {
      event.preventDefault();
      const speed = stateNow.current?.speed ?? 1;
      const options = key === '>' ? playbackSpeeds : [...playbackSpeeds].reverse();
      const next = options.find((value) => (key === '>' ? value > speed : value < speed));
      if (next !== undefined) {
        changeSpeed(next);
      }
    }
  };

  function retire() {
    generation.current++;
    playbackIntent.current++;
    preparing.current?.abort();
    preparing.current = null;
    player.current?.dispose();
    player.current = null;
    for (const subscription of subscriptions.current) {
      subscription.dispose();
    }
    subscriptions.current = [];
    emulator.current?.dispose();
    emulator.current = null;
    setBusy(false);
    setMetadata(null);
    setState(null);
    setFailure(null);
    setHelpOpen(false);
    stateNow.current = null;
    seekingIntent.current++;
    fullscreenIntent.current++;
    setPreview(null);
    setMediaClaimed(0);
    setControlsVisible(true);
    scrubbing.current = false;
    clearTimeout(hideTimer.current);
    if (video.current !== null && document.fullscreenElement === video.current) {
      void document.exitFullscreen().catch(() => {});
    }
  }
  // biome-ignore lint/correctness/useExhaustiveDependencies: Any immutable source/expectation or availability change must retire local renderer data and worker ownership.
  useEffect(() => {
    retire();
    return () => {
      generation.current++;
      preparing.current?.abort();
      preparing.current = null;
      player.current?.dispose();
      player.current = null;
      for (const subscription of subscriptions.current) {
        subscription.dispose();
      }
      subscriptions.current = [];
      emulator.current?.dispose();
      emulator.current = null;
      if (video.current !== null && document.fullscreenElement === video.current) {
        void document.exitFullscreen().catch(() => {});
      }
    };
  }, [source, expected.id, expected.producer, expected.allowUntrusted, disabled, preparedImage]);
  // A decoded immutable image represents one explicit open intent. Returning
  // to its tab, closing the player or a transient disabled state never replays it.
  // biome-ignore lint/correctness/useExhaustiveDependencies: Reset only for a new immutable source/expectation, never for availability or tab activation.
  useEffect(() => {
    automaticAttempt.current = false;
  }, [source, id, producer, allowUntrusted, preparedImage]);
  useEffect(() => {
    if (emulator.current !== null) {
      emulator.current.options.theme = {
        background: palette === 'dark' ? '#101820' : '#ffffff',
        foreground: palette === 'dark' ? '#e0e6ed' : '#1b2638',
      };
    }
  }, [palette]);

  const prepare = useCallback(async () => {
    if (disabled || preparing.current !== null || player.current !== null) {
      return;
    }
    const controller = new AbortController();
    const current = ++generation.current;
    preparing.current = controller;
    setBusy(true);
    setFailure(null);
    let image: Awaited<ReturnType<typeof prepareRecordingPlayback>> | null = null;
    try {
      image =
        preparedImage ??
        (await prepareRecordingPlayback(
          source,
          { id, producer, allowUntrusted },
          controller.signal,
        ));
      const { Terminal } = await import('@xterm/xterm');
      if (
        controller.signal.aborted ||
        current !== generation.current ||
        container.current === null
      ) {
        image.dispose();
        return;
      }
      const nonce =
        document.querySelector<HTMLMetaElement>('meta[name="bifroest-nonce"]')?.content ?? '';
      const terminal = new Terminal({
        allowProposedApi: false,
        disableStdin: true,
        cursorBlink: false,
        cursorStyle: 'block',
        cursorInactiveStyle: 'block',
        screenReaderMode: true,
        scrollback: 1000,
        fontSize: 13,
        fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace',
        cols: image.metadata.columns,
        rows: image.metadata.rows,
        documentOverride: noncedDocument(document, nonce),
        windowOptions: {},
        customGlyphs: true,
        linkHandler: { activate() {} },
        theme: {
          background: currentPalette.current === 'dark' ? '#101820' : '#ffffff',
          foreground: currentPalette.current === 'dark' ? '#e0e6ed' : '#1b2638',
        },
      });
      emulator.current = terminal;
      terminal.open(container.current);
      terminal.textarea?.setAttribute('aria-label', t('playbackViewport'));
      subscriptions.current.push(installTerminalRenderer(terminal, container.current));
      subscriptions.current.push(terminal.parser.registerOscHandler(52, () => true));
      if (video.current) {
        subscriptions.current.push(observePlaybackLayout(video.current, container.current));
      }
      await initializePlaybackCursor(terminal, controller.signal);
      if (
        controller.signal.aborted ||
        current !== generation.current ||
        emulator.current !== terminal
      ) {
        image.dispose();
        return;
      }
      const info = image.metadata;
      const recording = new RecordingPlayback(
        image,
        {
          write: (data, done) => terminal.write(data, done),
          resize: (columns, rows) => terminal.resize(columns, rows),
          reset: (columns, rows) => {
            terminal.reset();
            terminal.resize(columns, rows);
          },
        },
        (next) => {
          if (current === generation.current) {
            if (next.phase === 'failed') {
              reportUiError('playback', undefined, 'render-failed');
            }
            stateNow.current = next;
            setState(next);
          }
        },
      );
      image = null; // Ownership moved into the playback controller.
      player.current = recording;
      setMetadata(info);
      if (activeNow.current) {
        video.current?.scrollIntoView({ block: 'nearest' });
      }
    } catch (error) {
      image?.dispose();
      if (current === generation.current && !controller.signal.aborted) {
        reportUiError('playback', error);
        emulator.current?.dispose();
        emulator.current = null;
        for (const subscription of subscriptions.current) {
          subscription.dispose();
        }
        subscriptions.current = [];
        setFailure(
          error instanceof EvidenceError && error.code === 'limit'
            ? 'limit'
            : error instanceof EvidenceError && error.code === 'verification'
              ? 'verification'
              : 'unavailable',
        );
      }
    } finally {
      if (preparing.current === controller) {
        preparing.current = null;
        setBusy(false);
      }
    }
  }, [source, id, producer, allowUntrusted, disabled, preparedImage]);
  useEffect(() => {
    if (autoPrepare && active && !disabled && !automaticAttempt.current) {
      const current = generation.current;
      queueMicrotask(() => {
        if (
          current === generation.current &&
          automaticAllowed.current &&
          !automaticAttempt.current
        ) {
          automaticAttempt.current = true;
          void prepare();
        }
      });
    }
  }, [autoPrepare, active, disabled, prepare]);

  return (
    <section ref={playerSection} className="stack" aria-label={t('playbackTitle')}>
      <p id={helpID} className="recording-player-status">
        {t('playbackKeyboardHelp')}
      </p>
      {failure !== null && (
        <Alert role="status" color="red">
          {t(
            failure === 'limit'
              ? 'playbackLimit'
              : failure === 'verification'
                ? 'playbackVerificationFailed'
                : 'playbackUnavailable',
          )}
        </Alert>
      )}
      <div
        ref={video}
        className={`recording-video${palette === 'dark' ? ' recording-video--dark' : ''}`}
        role="application"
        aria-label={t('playbackVideo')}
        aria-describedby={helpID}
        // biome-ignore lint/a11y/noNoninteractiveTabindex: Focus enables media shortcuts; native controls remain separately keyboard accessible.
        tabIndex={0}
        data-controls-visible={controlsVisible}
        data-seeking={state?.phase === 'seeking' || state?.phase === 'resetting'}
        onPointerMove={() => reveal()}
        onPointerEnter={() => reveal()}
        onPointerDown={(event) => {
          if (helpOpen) {
            return;
          }
          reveal(false);
          claimMedia();
          if (!(event.target as HTMLElement).closest('.recording-controls')) {
            video.current?.focus({ preventScroll: true });
          }
        }}
        onKeyDownCapture={handleKey}
        onKeyDown={(event) => {
          if (event.defaultPrevented) {
            event.stopPropagation();
          }
        }}
        onFocusCapture={(event) => {
          reveal(keyboard.current || (event.target as Element).matches(':focus-visible'));
          claimMedia();
        }}
        onBlurCapture={() => reveal(keyboard.current)}
        onClick={(event) => {
          if (helpOpen) {
            return;
          }
          if (
            !(event.target as HTMLElement).closest('.recording-controls,button') &&
            !window.getSelection()?.toString()
          ) {
            toggle();
          }
        }}
      >
        <section ref={container} className="playback-surface" aria-label={t('playbackViewport')} />
        {metadata === null && (
          <div className="recording-overlay">
            {busy ? (
              <div className="recording-loading">
                <p>{t('playbackPreparing')}</p>
                <ReadProgress value={null} />
              </div>
            ) : onPrepare ? (
              <Button disabled={disabled} onClick={onPrepare}>
                {t('recordingOpen')}
              </Button>
            ) : verificationControls !== undefined ? (
              <span>{t('recordingOpen')}</span>
            ) : (
              <Button
                disabled={disabled}
                onClick={() => {
                  automaticAttempt.current = true;
                  void prepare();
                }}
              >
                {t('playbackPrepare')}
              </Button>
            )}
          </div>
        )}
        {(state?.phase === 'seeking' || state?.phase === 'resetting') && (
          <div className="recording-overlay" role="status">
            {t('playbackSeeking')}
          </div>
        )}
        {state?.phase === 'failed' && (
          <div className="recording-overlay" role="alert">
            {t('playbackRenderFailed')}
          </div>
        )}
        <div ref={toolbar}>
          <div className="recording-verification">
            {busy ? (
              <IconButton color="inherit" aria-label={t('artifactCancel')} onClick={retire}>
                <CancelIcon />
              </IconButton>
            ) : (
              verificationControls
            )}
          </div>
          {(busy || metadata !== null || verificationControls !== undefined) && (
            <PlaybackControls
              state={state}
              durationUs={metadata?.durationUs ?? 0}
              preview={preview}
              disabled={disabled || busy || metadata === null || state?.phase === 'failed'}
              fullscreen={fullscreen}
              canFullscreen={typeof document.documentElement.requestFullscreen === 'function'}
              onToggle={toggle}
              onRestart={restart}
              onSeek={seek}
              onPreview={setPreview}
              onScrub={(value) => {
                scrubbing.current = value;
                reveal();
              }}
              onSpeed={changeSpeed}
              onFullscreen={toggleFullscreen}
              onHelp={() => {
                pause();
                setHelpOpen(true);
              }}
              onClose={retire}
            />
          )}
        </div>
        <Dialog
          open={helpOpen}
          onClose={() => setHelpOpen(false)}
          fullWidth
          maxWidth="sm"
          container={fullscreen ? video.current : undefined}
          aria-labelledby={`${helpID}-title`}
        >
          <DialogTitle id={`${helpID}-title`}>{t('playbackHelp')}</DialogTitle>
          <DialogContent className="stack">
            <p>{t('playbackLocalOnly')}</p>
            <p>{t('playbackKeyboardHelp')}</p>
            {metadata && (
              <>
                <p>
                  {t(
                    metadata.trust === 'pinned'
                      ? 'recordingIdentityPinned'
                      : metadata.trust === 'not-checked'
                        ? 'recordingIdentityUnchecked'
                        : 'recordingIdentityUnknown',
                  )}
                </p>
                <p>
                  {t('playbackRecordedStatus')}:{' '}
                  {t(
                    metadata.status === 'completed'
                      ? 'artifactCatalogCompleted'
                      : metadata.status === 'failed'
                        ? 'artifactCatalogFailedStatus'
                        : 'artifactCatalogIncomplete',
                  )}
                  {metadata.exitStatus === null ? '' : ` / ${metadata.exitStatus}`}
                </p>
              </>
            )}
          </DialogContent>
          <DialogActions>
            <Button variant="subtle" onClick={() => setHelpOpen(false)}>
              {t('close')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
      {fullscreenFailed && (
        <Alert role="status" color="yellow">
          {t('playbackFullscreenFailed')}
        </Alert>
      )}
      {metadata && (
        <p
          className="recording-player-status"
          role="status"
          data-playback-phase={state?.phase ?? 'paused'}
        >
          {t(
            state?.phase === 'playing'
              ? 'playbackPlaying'
              : state?.phase === 'ended'
                ? 'playbackEnded'
                : state?.phase === 'failed'
                  ? 'playbackRenderFailed'
                  : state?.phase === 'seeking' || state?.phase === 'resetting'
                    ? 'playbackSeeking'
                    : 'playbackPaused',
          )}{' '}
          ({playbackClock(state?.positionUs ?? 0)} / {playbackClock(metadata.durationUs)})
        </p>
      )}
    </section>
  );
}
