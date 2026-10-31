import type { IDisposable, Terminal as Xterm } from '@xterm/xterm';
import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Select, Title, useComputedColorScheme } from '../ui/material';
import '@xterm/xterm/css/xterm.css';
import { noncedDocument } from '../terminal/document';
import { reportUiError } from '../ui/error-report';
import { t } from '../ui/messages';
import { EvidenceError } from './evidence-protocol';
import type { PlaybackState } from './playback';
import { RecordingPlayback } from './playback';
import type { PlaybackMetadata, PlaybackOptions } from './playback-protocol';
import { prepareRecordingPlayback } from './prepare-playback';

export function RecordingPlayer({
  source,
  expected,
  disabled,
}: {
  source: Blob;
  expected: PlaybackOptions;
  disabled: boolean;
}) {
  const container = useRef<HTMLElement | null>(null);
  const preparing = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const emulator = useRef<Xterm | null>(null);
  const player = useRef<RecordingPlayback | null>(null);
  const subscriptions = useRef<IDisposable[]>([]);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<'limit' | 'verification' | 'unavailable' | null>(null);
  const [metadata, setMetadata] = useState<PlaybackMetadata | null>(null);
  const [state, setState] = useState<PlaybackState | null>(null);
  const palette = useComputedColorScheme('light');
  const currentPalette = useRef(palette);
  currentPalette.current = palette;

  function retire() {
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
    setBusy(false);
    setMetadata(null);
    setState(null);
    setFailure(null);
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
    };
  }, [source, expected.id, expected.producer, expected.allowUntrusted, disabled]);
  useEffect(() => {
    if (emulator.current !== null) {
      emulator.current.options.theme = {
        background: palette === 'dark' ? '#101820' : '#ffffff',
        foreground: palette === 'dark' ? '#e0e6ed' : '#1b2638',
      };
    }
  }, [palette]);

  async function prepare() {
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
      image = await prepareRecordingPlayback(source, expected, controller.signal);
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
        screenReaderMode: true,
        scrollback: 1000,
        fontSize: 13,
        fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace',
        cols: image.metadata.columns,
        rows: image.metadata.rows,
        documentOverride: noncedDocument(document, nonce),
        windowOptions: {},
        linkHandler: { activate() {} },
        theme: {
          background: currentPalette.current === 'dark' ? '#101820' : '#ffffff',
          foreground: currentPalette.current === 'dark' ? '#e0e6ed' : '#1b2638',
        },
      });
      emulator.current = terminal;
      terminal.open(container.current);
      subscriptions.current.push(terminal.parser.registerOscHandler(52, () => true));
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
            setState(next);
          }
        },
      );
      image = null; // Ownership moved into the playback controller.
      player.current = recording;
      setMetadata(info);
      container.current.scrollIntoView({ block: 'nearest' });
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
  }

  return (
    <section className="stack" aria-label={t('playbackTitle')}>
      <Title order={4}>{t('playbackTitle')}</Title>
      <Alert color="blue">{t('playbackLocalOnly')}</Alert>
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
      <div className="actions">
        <Button
          disabled={disabled || busy || metadata !== null}
          onClick={() => {
            void prepare();
          }}
        >
          {t('playbackPrepare')}
        </Button>
        {(busy || metadata !== null) && (
          <Button variant="default" onClick={retire}>
            {t('playbackDiscard')}
          </Button>
        )}
      </div>
      {busy && <p role="status">{t('playbackPreparing')}</p>}
      {metadata !== null && (
        <>
          <p>
            {t(metadata.trust === 'pinned' ? 'artifactPinnedResult' : 'artifactUntrustedResult')}
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
          <div className="actions">
            <Button
              disabled={disabled || state?.phase !== 'paused'}
              onClick={() => player.current?.play()}
            >
              {t('playbackPlay')}
            </Button>
            <Button
              disabled={disabled || state?.phase !== 'playing'}
              onClick={() => player.current?.pause()}
            >
              {t('playbackPause')}
            </Button>
            <Button
              disabled={disabled || state?.phase === 'resetting' || state?.phase === 'failed'}
              onClick={() => {
                void player.current?.restart();
              }}
            >
              {t('playbackRestart')}
            </Button>
            <Select
              label={t('playbackSpeed')}
              data={['0.25', '0.5', '1', '2', '4', '8']}
              value={String(state?.speed ?? 1)}
              disabled={disabled || state?.phase === 'resetting' || state?.phase === 'failed'}
              onChange={(value) => player.current?.speed(Number(value))}
            />
          </div>
          <p role="status" data-playback-phase={state?.phase ?? 'paused'}>
            {t(
              state?.phase === 'playing'
                ? 'playbackPlaying'
                : state?.phase === 'ended'
                  ? 'playbackEnded'
                  : state?.phase === 'failed'
                    ? 'playbackRenderFailed'
                    : state?.phase === 'resetting'
                      ? 'playbackResetting'
                      : 'playbackPaused',
            )}{' '}
            (
            {new Intl.NumberFormat('en-US', { maximumFractionDigits: 2 }).format(
              (state?.positionUs ?? 0) / 1_000_000,
            )}{' '}
            /{' '}
            {new Intl.NumberFormat('en-US', { maximumFractionDigits: 2 }).format(
              metadata.durationUs / 1_000_000,
            )}{' '}
            {t('playbackSeconds')})
          </p>
        </>
      )}
      <section ref={container} className="playback-surface" aria-label={t('playbackViewport')} />
    </section>
  );
}
