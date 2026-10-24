import { useEffect, useRef, useState } from 'react';
import { Button, Checkbox, Paper, SegmentedControl, TextInput, Title, useComputedColorScheme } from '@mantine/core';
import type { Terminal as Xterm, IDisposable, ITheme } from '@xterm/xterm';
import type { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import type { WebAccess } from '../remember';
import { TerminalConnection } from './socket';
import type { TerminalState } from './socket';
import { noncedDocument } from './document';
import { t } from '../ui/messages';
import type { Message } from '../ui/messages';

const dark: ITheme = { background: '#101820', foreground: '#e0e6ed', cursor: '#ffffff', selectionBackground: '#47596b' };
const light: ITheme = { background: '#ffffff', foreground: '#1b2638', cursor: '#1b2638', selectionBackground: '#c4ddf0' };

function flushRenderer(terminal: Xterm, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const finish = (error?: Error) => { clearTimeout(timer); signal.removeEventListener('abort', aborted); error === undefined ? resolve() : reject(error); };
    const aborted = () => finish(new Error('terminal start cancelled'));
    const timer = setTimeout(() => finish(new Error('terminal renderer did not drain')), 5000);
    signal.addEventListener('abort', aborted, { once: true });
    if (signal.aborted) { aborted(); return; }
    try { terminal.write('', () => finish()); } catch { finish(new Error('terminal renderer unavailable')); }
  });
}

function statusKey(state: TerminalState | null): Message {
  if (state === null) return 'terminalIdle';
  if (state.phase === 'connecting') return 'terminalConnecting';
  if (state.phase === 'connected') return 'terminalConnected';
  if (state.phase === 'finishing') return 'terminalFinishing';
  if (state.phase === 'exited') return 'terminalExited';
  if (state.phase === 'disconnected') return 'terminalDisconnected';
  return state.reason === 'configuration' ? 'terminalConfiguration' : state.reason === 'access-required' ? 'terminalAccessRequired' : state.reason === 'input-limit' ? 'terminalInputLimit' : state.reason === 'output-limit' ? 'terminalOutputLimit' : state.reason === 'server-error' ? 'terminalServerError' : state.reason === 'protocol' ? 'terminalProtocol' : state.reason === 'timeout' ? 'terminalTimeout' : 'terminalInterrupted';
}

export function TerminalPanel({ access, disabled }: { access: WebAccess; disabled: boolean }) {
  const container = useRef<HTMLDivElement | null>(null);
  const currentAccess = useRef(access); currentAccess.current = access;
  const emulator = useRef<Xterm | null>(null);
  const fit = useRef<FitAddon | null>(null);
  const connection = useRef<TerminalConnection | null>(null);
  const pendingStart = useRef<AbortController | null>(null);
  const alive = useRef(true);
  const palette = useComputedColorScheme('light');
  const currentPalette = useRef(palette); currentPalette.current = palette;
  const [initialized, setInitialized] = useState(false);
  const [unavailable, setUnavailable] = useState(false);
  const [state, setState] = useState<TerminalState | null>(null);
  const [kind, setKind] = useState('shell');
  const [pty, setPty] = useState(true);
  const [inputClosed, setInputClosed] = useState(false);
  const [principal, setPrincipal] = useState('');
  const running = state?.phase === 'connecting' || state?.phase === 'connected' || state?.phase === 'finishing';

  useEffect(() => {
    alive.current = true;
    let disposed = false;
    let observer: ResizeObserver | undefined, resizeTimer: ReturnType<typeof setTimeout> | undefined;
    const subscriptions: IDisposable[] = [];
    void Promise.all([import('@xterm/xterm'), import('@xterm/addon-fit')]).then(([module, addon]) => {
      if (disposed || container.current === null) return;
      const nonce = document.querySelector<HTMLMetaElement>('meta[name="bifroest-nonce"]')?.content ?? '';
      const terminal = new module.Terminal({
        allowProposedApi: false, disableStdin: true, cursorBlink: true, screenReaderMode: true,
        scrollback: 1000, fontSize: 13, fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace',
        documentOverride: noncedDocument(document, nonce), windowOptions: {},
        theme: currentPalette.current === 'dark' ? dark : light,
        linkHandler: { activate() {} }, // No server-directed URLs, popups or clipboard addon.
      });
      emulator.current = terminal;
      const addonFit = new addon.FitAddon(); fit.current = addonFit;
      terminal.loadAddon(addonFit); terminal.open(container.current);
      subscriptions.push(terminal.parser.registerOscHandler(52, () => true)); // Ignore remote clipboard requests.
      subscriptions.push(terminal.onData(value => {
        if (value.length > 64 << 10) { connection.current?.input(new Uint8Array((64 << 10) + 1)); return; }
        connection.current?.input(new TextEncoder().encode(value));
      }));
      subscriptions.push(terminal.onBinary(value => {
        if (value.length > 64 << 10) { connection.current?.input(new Uint8Array((64 << 10) + 1)); return; }
        connection.current?.input(Uint8Array.from(value, character => character.charCodeAt(0)));
      }));
      const resize = () => {
        if (disposed || container.current === null || container.current.clientWidth === 0) return;
        try {
          const before = `${terminal.cols}:${terminal.rows}`; addonFit.fit();
          if (before !== `${terminal.cols}:${terminal.rows}`) connection.current?.resize(terminal.cols, terminal.rows);
        } catch { /* A hidden/resizing container is retried by the owned observer. */ }
      };
      observer = new ResizeObserver(() => { clearTimeout(resizeTimer); resizeTimer = setTimeout(resize, 120); });
      observer.observe(container.current); resize(); setInitialized(true);
    }).catch(() => { if (!disposed) setUnavailable(true); });
    return () => {
      disposed = true; clearTimeout(resizeTimer); observer?.disconnect();
      alive.current = false; pendingStart.current?.abort(); pendingStart.current = null;
      connection.current?.dispose(); connection.current = null;
      for (const subscription of subscriptions) subscription.dispose();
      emulator.current?.dispose(); emulator.current = null; fit.current = null;
    };
  }, []);
  useEffect(() => { if (emulator.current !== null) emulator.current.options.theme = palette === 'dark' ? dark : light; }, [palette]);

  async function start(form: HTMLFormElement) {
    if (running || disabled || emulator.current === null || pendingStart.current !== null) return;
    const terminal = emulator.current;
    const selected = currentAccess.current;
    const command = (form.elements.namedItem('command') as HTMLInputElement | null)?.value ?? '';
    if (!command.isWellFormed() || command.includes('\0') || new TextEncoder().encode(command).byteLength > 4096) { setState({ phase: 'interrupted', reason: 'configuration' }); return; }
    const controller = new AbortController(); pendingStart.current = controller;
    connection.current?.dispose(); connection.current = null;
    terminal.options.disableStdin = true;
    setState({ phase: 'connecting' });
    try {
      // Drain the old emulator job before reset: an interrupted write must not
      // bleed output into a new execution/actor, even after driver disposal.
      await flushRenderer(terminal, controller.signal);
      if (!alive.current || controller.signal.aborted) return;
      terminal.reset();
      try { fit.current?.fit(); } catch { /* Keep last valid dimensions if temporarily hidden. */ }
      setInputClosed(false); setPrincipal(selected.snapshot().principal);
      connection.current = new TerminalConnection(selected, { kind: kind === 'exec' ? 'exec' : 'shell', command, pty, columns: terminal.cols, rows: terminal.rows },
        { write(_channel, data, done) { terminal.write(data, done); } },
        next => {
          terminal.options.disableStdin = next.phase !== 'connected'; setState(next);
          if (next.phase === 'connected') { container.current?.scrollIntoView({ block: 'nearest' }); terminal.focus(); }
        });
      terminal.focus();
    } catch { if (alive.current && !controller.signal.aborted) setState({ phase: 'interrupted', reason: 'access-required' }); }
    finally { if (pendingStart.current === controller) pendingStart.current = null; }
  }

  function disconnect() {
    pendingStart.current?.abort(); pendingStart.current = null;
    if (connection.current !== null) connection.current.disconnect();
    else setState({ phase: 'disconnected' });
  }

  return <Paper withBorder p="lg" className="stack terminal-panel">
    <Title order={2}>{t('terminalTitle')}</Title>
    <p className="caption">{t('terminalFresh')}</p>
    <form method="post" action="/_bifroest/api/v1/terminal" className="stack" onSubmit={event => { event.preventDefault(); void start(event.currentTarget); }}>
      <SegmentedControl aria-label={t('terminalTask')} value={kind} onChange={setKind} disabled={running || disabled} data={[{ value: 'shell', label: t('terminalShell') }, { value: 'exec', label: t('terminalExec') }]} />
      {kind === 'exec' && <TextInput name="command" label={t('terminalCommand')} autoComplete="off" disabled={running || disabled} />}
      <Checkbox label={t('terminalPty')} checked={pty} onChange={event => setPty(event.currentTarget.checked)} disabled={running || disabled} />
      <div className="actions"><Button type="submit" disabled={!initialized || running || disabled}>{t('terminalStart')}</Button><Button variant="default" disabled={state?.phase !== 'connecting' && state?.phase !== 'connected'} onClick={disconnect}>{t('terminalDisconnect')}</Button></div>
    </form>
    <p role="status" data-terminal-phase={state?.phase ?? 'idle'}>{t(unavailable ? 'terminalUnavailable' : !initialized ? 'terminalLoading' : statusKey(state))}{state?.phase === 'exited' ? ` ${new Intl.NumberFormat('en-US', { useGrouping: false }).format(state.status)}` : ''}</p>
    {principal !== '' && <p className="caption">{t('terminalActor')}: {principal}</p>}
    <div className="terminal-surface" ref={container} aria-label={t('terminalViewport')} />
    <div className="actions">
      <Button variant="default" disabled={state?.phase !== 'connected' || inputClosed} onClick={() => { if (connection.current?.eof()) { setInputClosed(true); if (emulator.current) emulator.current.options.disableStdin = true; } }}>{t('terminalEof')}</Button>
      <Button variant="default" disabled={state?.phase !== 'connected'} onClick={() => connection.current?.signal('INT')}>{t('terminalInterrupt')}</Button>
      <Button variant="default" disabled={state?.phase !== 'connected'} onClick={() => connection.current?.signal('TERM')}>{t('terminalTerminate')}</Button>
    </div>
  </Paper>;
}
