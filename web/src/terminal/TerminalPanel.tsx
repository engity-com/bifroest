import { useComputedColorScheme } from '@mantine/core';
import type { IDisposable, ITheme, Terminal as Xterm } from '@xterm/xterm';
import { useEffect, useRef } from 'react';
import '@xterm/xterm/css/xterm.css';
import type { WebAccess } from '../remember';
import type { Message } from '../ui/messages';
import { t } from '../ui/messages';
import { noncedDocument } from './document';
import type { TerminalState } from './socket';
import { TerminalConnection } from './socket';

const dark: ITheme = {
  background: '#101820',
  foreground: '#e0e6ed',
  cursor: '#ffffff',
  selectionBackground: '#47596b',
};
const light: ITheme = {
  background: '#ffffff',
  foreground: '#1b2638',
  cursor: '#1b2638',
  selectionBackground: '#c4ddf0',
};

export interface TerminalActions {
  eof(): boolean;
  signal(value: 'INT' | 'TERM'): boolean;
  disconnect(): void;
}

export function terminalStatus(state: TerminalState): Message {
  switch (state.phase) {
    case 'connecting':
      return 'terminalConnecting';
    case 'connected':
      return 'terminalConnected';
    case 'finishing':
      return 'terminalFinishing';
    case 'exited':
      return 'terminalExited';
    case 'disconnected':
      return 'terminalDisconnected';
    default:
      return state.reason === 'configuration'
        ? 'terminalConfiguration'
        : state.reason === 'access-required'
          ? 'terminalAccessRequired'
          : state.reason === 'input-limit'
            ? 'terminalInputLimit'
            : state.reason === 'output-limit'
              ? 'terminalOutputLimit'
              : state.reason === 'server-error'
                ? 'terminalServerError'
                : state.reason === 'protocol'
                  ? 'terminalProtocol'
                  : state.reason === 'timeout'
                    ? 'terminalTimeout'
                    : 'terminalInterrupted';
  }
}

// The access and cancellation signal belong to this tab for its entire life.
// A tab mounts one shell once. Changing focus, theme or the current login never
// opens another connection or assigns a different actor to its existing output.
export function TerminalPanel({
  id,
  access,
  signal,
  active,
  inputAllowed,
  focusOnActivate,
  onState,
  onActions,
}: {
  id: number;
  access: WebAccess;
  signal: AbortSignal;
  active: boolean;
  inputAllowed: boolean;
  focusOnActivate: boolean;
  onState: (id: number, state: TerminalState) => void;
  onActions: (id: number, actions: TerminalActions | null) => void;
}) {
  const container = useRef<HTMLElement | null>(null);
  const emulator = useRef<Xterm | null>(null);
  const layout = useRef<(() => void) | null>(null);
  const state = useRef<TerminalState>({ phase: 'connecting' });
  const eof = useRef(false);
  const interaction = useRef({ active, inputAllowed, focusOnActivate });
  interaction.current = { active, inputAllowed, focusOnActivate };
  const palette = useComputedColorScheme('light');
  const currentPalette = useRef(palette);
  currentPalette.current = palette;

  useEffect(() => {
    let disposed = false;
    let connection: TerminalConnection | null = null;
    let observer: ResizeObserver | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const subscriptions: IDisposable[] = [];
    const updateInput = () => {
      if (emulator.current) {
        emulator.current.options.disableStdin =
          !interaction.current.active ||
          !interaction.current.inputAllowed ||
          eof.current ||
          state.current.phase !== 'connected';
      }
    };
    const stop = () => {
      disposed = true;
      connection?.dispose();
      onActions(id, null);
      if (emulator.current) {
        emulator.current.options.disableStdin = true;
      }
    };
    signal.addEventListener('abort', stop, { once: true });
    if (signal.aborted) {
      stop();
    }
    void Promise.all([import('@xterm/xterm'), import('@xterm/addon-fit')])
      .then(([module, addon]) => {
        if (disposed || container.current === null) {
          return;
        }
        const nonce =
          document.querySelector<HTMLMetaElement>('meta[name="bifroest-nonce"]')?.content ?? '';
        const terminal = new module.Terminal({
          allowProposedApi: false,
          disableStdin: true,
          cursorBlink: true,
          screenReaderMode: true,
          scrollback: 1000,
          fontSize: 14,
          fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace',
          documentOverride: noncedDocument(document, nonce),
          windowOptions: {},
          theme: currentPalette.current === 'dark' ? dark : light,
          linkHandler: { activate() {} },
        });
        emulator.current = terminal;
        const fit = new addon.FitAddon();
        terminal.loadAddon(fit);
        terminal.open(container.current);
        subscriptions.push(terminal.parser.registerOscHandler(52, () => true));
        const mayInput = () =>
          !disposed &&
          interaction.current.active &&
          interaction.current.inputAllowed &&
          !eof.current;
        subscriptions.push(
          terminal.onData((value) => {
            if (mayInput()) {
              connection?.input(
                value.length > 64 << 10
                  ? new Uint8Array((64 << 10) + 1)
                  : new TextEncoder().encode(value),
              );
            }
          }),
        );
        subscriptions.push(
          terminal.onBinary((value) => {
            if (mayInput()) {
              connection?.input(
                value.length > 64 << 10
                  ? new Uint8Array((64 << 10) + 1)
                  : Uint8Array.from(value, (character) => character.charCodeAt(0)),
              );
            }
          }),
        );
        const resize = () => {
          if (disposed || !container.current?.clientWidth || !container.current.clientHeight) {
            return;
          }
          try {
            const before = `${terminal.cols}:${terminal.rows}`;
            fit.fit();
            if (before !== `${terminal.cols}:${terminal.rows}`) {
              connection?.resize(terminal.cols, terminal.rows);
            }
          } catch {
            /* A hidden pane is fitted when selected again. */
          }
        };
        layout.current = resize;
        observer = new ResizeObserver(() => {
          clearTimeout(timer);
          timer = setTimeout(resize, 120);
        });
        observer.observe(container.current);
        resize();
        if (disposed || signal.aborted) {
          return;
        }
        connection = new TerminalConnection(
          access,
          { kind: 'shell', command: '', pty: true, columns: terminal.cols, rows: terminal.rows },
          {
            write(_channel, data, done) {
              terminal.write(data, done);
            },
          },
          (next) => {
            if (disposed) {
              return;
            }
            state.current = next;
            updateInput();
            onState(id, next);
            if (
              next.phase === 'connected' &&
              interaction.current.active &&
              interaction.current.inputAllowed &&
              interaction.current.focusOnActivate &&
              !document.activeElement?.closest('[role="tablist"]')
            ) {
              terminal.focus();
            }
          },
        );
        onActions(id, {
          eof() {
            if (!connection?.eof()) {
              return false;
            }
            eof.current = true;
            updateInput();
            return true;
          },
          signal(value) {
            return connection?.signal(value) ?? false;
          },
          disconnect() {
            connection?.disconnect();
          },
        });
      })
      .catch(() => {
        if (!disposed) {
          state.current = { phase: 'interrupted', reason: 'configuration' };
          onState(id, state.current);
        }
      });
    return () => {
      stop();
      signal.removeEventListener('abort', stop);
      clearTimeout(timer);
      observer?.disconnect();
      for (const subscription of subscriptions) {
        subscription.dispose();
      }
      emulator.current?.dispose();
      emulator.current = null;
      layout.current = null;
    };
  }, [id, access, signal, onState, onActions]);

  useEffect(() => {
    if (emulator.current) {
      emulator.current.options.theme = palette === 'dark' ? dark : light;
    }
  }, [palette]);
  useEffect(() => {
    if (emulator.current) {
      emulator.current.options.disableStdin =
        !active || !inputAllowed || eof.current || state.current.phase !== 'connected';
    }
    if (!active) {
      return;
    }
    const frame = requestAnimationFrame(() => {
      layout.current?.();
      if (focusOnActivate && inputAllowed && !document.activeElement?.closest('[role="tablist"]')) {
        emulator.current?.focus();
      }
    });
    return () => cancelAnimationFrame(frame);
  }, [active, inputAllowed, focusOnActivate]);

  return (
    <section className="terminal-surface" ref={container} aria-label={t('terminalViewport')} />
  );
}
