import CancelIcon from '@mui/icons-material/Cancel';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import { Box, Button, Stack, Typography, useTheme } from '@mui/material';
import type { IDisposable, Terminal as Xterm } from '@xterm/xterm';
import { useEffect, useRef } from 'react';
import { verificationLink } from '../login/links';
import { AuthenticationInput, authenticationText } from '../login/terminal-input';
import type { LoginStep, Scope } from '../remember';
import { reportUiError } from '../ui/error-report';
import { t } from '../ui/messages';
import { protectAuthenticationComposition } from './authentication-composition';
import { noncedDocument } from './document';
import '@xterm/xterm/css/xterm.css';

export interface AuthenticationView {
  readonly id: number;
  readonly scope: Scope;
  readonly user: string;
  readonly step: LoginStep | null;
  readonly pending: boolean;
  readonly remembering: boolean;
  readonly message: string | null;
  readonly provider: LoginStep | null;
  readonly onAnswer: (value: string) => void;
  readonly onCancel: () => void;
}

// A local login console. It has no WebAccess, WebSocket, recording sink, remote
// command or session ID. Only BrowserClient's existing prompt handler receives
// each one-time answer; the real shell gets a separate renderer after success.
export function AuthenticationTerminal({
  view,
  active,
}: {
  view: AuthenticationView;
  active: boolean;
}) {
  const container = useRef<HTMLElement | null>(null);
  const terminal = useRef<Xterm | null>(null);
  const editor = useRef(new AuthenticationInput());
  const ready = useRef<LoginStep | null>(null);
  const composition = useRef<ReturnType<typeof protectAuthenticationComposition> | null>(null);
  const current = useRef({ view, active });
  current.current = { view, active };
  const shown = useRef<string | null>(null);
  const redraw = useRef<(() => void) | null>(null);
  const mode = useTheme().palette.mode;
  const background = mode === 'dark' ? '#101820' : '#ffffff';
  const providerURL = view.provider ? verificationLink(view.provider.message) : null;

  useEffect(() => {
    shown.current = null;
    let disposed = false;
    let observer: ResizeObserver | undefined;
    const nativeComposition = container.current
      ? protectAuthenticationComposition(
          container.current,
          () => {
            const owned = current.current;
            return owned.active && owned.view.pending && ready.current === owned.view.step
              ? owned.view.step
              : null;
          },
          () => current.current.view.onCancel(),
        )
      : null;
    composition.current = nativeComposition;
    const subscriptions: IDisposable[] = [];
    void Promise.all([import('@xterm/xterm'), import('@xterm/addon-fit')])
      .then(([module, addon]) => {
        if (disposed || !container.current) {
          return;
        }
        const renderer = new module.Terminal({
          disableStdin: false,
          cursorBlink: true,
          screenReaderMode: false,
          scrollback: 100,
          fontSize: 14,
          fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace',
          documentOverride: noncedDocument(
            document,
            document.querySelector<HTMLMetaElement>('meta[name="bifroest-nonce"]')?.content ?? '',
          ),
          windowOptions: {},
          linkHandler: { activate() {} },
          theme: { background, foreground: mode === 'dark' ? '#e0e6ed' : '#1b2638' },
        });
        terminal.current = renderer;
        const fit = new addon.FitAddon();
        renderer.loadAddon(fit);
        renderer.open(container.current);
        container.current
          .querySelector('textarea')
          ?.setAttribute('aria-label', t('authenticationResponse'));
        const render = () => {
          const { view: owned, active: visible } = current.current;
          const key = owned.step
            ? `step:${owned.step.sequence}`
            : owned.message
              ? `error:${owned.message}`
              : owned.remembering
                ? 'remembering'
                : 'waiting';
          if (shown.current !== key) {
            if (owned.step?.kind === 'error') {
              reportUiError('authentication-provider', undefined, 'provider-error');
            }
            if (!nativeComposition?.check()) {
              return;
            }
            shown.current = key;
            editor.current.clear();
            ready.current = null;
            if (container.current) {
              const input = container.current.querySelector('textarea');
              if (input) {
                input.value = '';
              }
              const preedit = container.current.querySelector('.composition-view');
              if (preedit) {
                preedit.textContent = '';
              }
              container.current.dataset.authReady = 'false';
            }
            const text = owned.step
              ? `${owned.step.message}${owned.step.kind === 'prompt' ? ' ' : `\n${t('authenticationContinue')}`}`
              : (owned.message ??
                t(owned.remembering ? 'loginRemembering' : 'authenticationWaiting'));
            renderer.write(
              `${authenticationText(text)}${owned.step?.kind === 'prompt' ? '' : '\r\n'}`,
              () => {
                if (
                  disposed ||
                  shown.current !== key ||
                  current.current.view.step !== owned.step ||
                  !container.current
                ) {
                  return;
                }
                editor.current.reset(owned.step);
                ready.current = owned.step;
                container.current.dataset.authReady = owned.step ? 'true' : 'false';
                container.current.dataset.authKind = owned.step?.kind ?? '';
                container.current.dataset.authSequence = owned.step?.sequence ?? '';
                container.current.dataset.authEcho = String(owned.step?.echo ?? false);
                if (current.current.active) {
                  renderer.focus();
                }
              },
            );
          }
          renderer.options.disableStdin = !visible || !owned.pending;
          // xterm's screen-reader input mirror must not announce secret keys.
          // The safe prompt itself remains in the separate live region below.
          renderer.options.screenReaderMode = owned.step?.kind === 'prompt' && owned.step.echo;
          if (visible) {
            fit.fit();
            renderer.focus();
          }
        };
        redraw.current = render;
        subscriptions.push(
          renderer.onData((data) => {
            const owned = current.current;
            if (!owned.active || !owned.view.pending) {
              return;
            }
            if (!nativeComposition?.check()) {
              return;
            }
            if (nativeComposition.pending() && /[\r\n]/u.test(data)) {
              owned.view.onCancel();
              return;
            }
            if (
              ready.current !== owned.view.step &&
              !data.includes('\x03') &&
              !data.includes('\x04')
            ) {
              return;
            }
            const result = editor.current.consume(data);
            if (result.display) {
              renderer.write(result.display);
            }
            if (result.cancelled) {
              owned.view.onCancel();
            } else if (result.answer !== undefined) {
              ready.current = null;
              if (container.current) {
                container.current.dataset.authReady = 'false';
              }
              owned.view.onAnswer(result.answer);
            }
          }),
        );
        observer = new ResizeObserver(() => {
          if (current.current.active) {
            fit.fit();
          }
        });
        observer.observe(container.current);
        render();
      })
      .catch((error) => {
        if (!disposed) {
          reportUiError('authentication-terminal', error, 'configuration');
          current.current.view.onCancel();
        }
      });
    return () => {
      disposed = true;
      redraw.current = null;
      editor.current.clear();
      ready.current = null;
      nativeComposition?.dispose();
      composition.current = null;
      observer?.disconnect();
      for (const subscription of subscriptions) {
        subscription.dispose();
      }
      terminal.current?.dispose();
      terminal.current = null;
    };
  }, [background, mode]);
  useEffect(() => {
    current.current = { view, active };
    redraw.current?.();
  }, [view, active]);

  return (
    <div className="authentication-workspace">
      <Box
        aria-live="polite"
        sx={{
          position: 'absolute',
          width: 1,
          height: 1,
          overflow: 'hidden',
          clipPath: 'inset(50%)',
        }}
      >
        {view.step?.message ?? view.message ?? t('authenticationWaiting')}
      </Box>
      <Stack direction="row" spacing={1} sx={{ alignItems: 'center', px: 1, py: 0.5 }}>
        <Typography variant="body2" sx={{ flexGrow: 1 }}>
          {view.pending ? t('authenticationInProgress') : t('authenticationStopped')}
        </Typography>
        {providerURL && (
          <Button
            component="a"
            href={providerURL}
            target="_blank"
            rel="noopener noreferrer"
            referrerPolicy="no-referrer"
            size="small"
            startIcon={<OpenInNewIcon />}
          >
            {t('verificationLink')}
          </Button>
        )}
        <Button size="small" color="inherit" startIcon={<CancelIcon />} onClick={view.onCancel}>
          {view.pending ? t('cancel') : t('close')}
        </Button>
      </Stack>
      <section
        ref={container}
        className="terminal-surface authentication-surface"
        aria-label={t('authenticationTerminal')}
        style={{ backgroundColor: background, padding: 4 }}
        onContextMenuCapture={(event) => event.preventDefault()}
        onPasteCapture={(event) => {
          event.preventDefault();
          event.stopPropagation();
          if (!current.current.active || !current.current.view.pending) {
            return;
          }
          if (composition.current?.pending()) {
            current.current.view.onCancel();
            return;
          }
          if (ready.current !== current.current.view.step) {
            return;
          }
          const result = editor.current.consume(event.clipboardData.getData('text'));
          if (result.display) {
            terminal.current?.write(result.display);
          }
          if (result.cancelled) {
            current.current.view.onCancel();
          } else if (result.answer !== undefined) {
            ready.current = null;
            if (container.current) {
              container.current.dataset.authReady = 'false';
            }
            current.current.view.onAnswer(result.answer);
          }
        }}
      />
    </div>
  );
}
