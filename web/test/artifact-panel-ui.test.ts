import { act, createElement, StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ArtifactPanel } from '../src/artifacts/ArtifactPanel';
import type {
  EvidenceMetadata,
  EvidenceOptions,
  VerifiedArtifact,
} from '../src/artifacts/evidence-protocol';
import { EvidenceError } from '../src/artifacts/evidence-protocol';
import { inspectProtection } from '../src/artifacts/protection';
import type { ArtifactRequest, ReceivedArtifact } from '../src/artifacts/protocol';
import { ArtifactSecretsContext, useTabArtifactSecrets } from '../src/artifacts/session-secrets';
import { verifyArtifact } from '../src/artifacts/verify';
import { WebAccess } from '../src/remember/client';
import { Http } from '../src/remember/http';
import { t } from '../src/ui/messages';
import '../src/ui/app.css';

const recording = {
  kind: 'recording',
  auditlog: 'default',
  id: '34e34ab8-7457-4d88-a5e4-c57791775c3a',
} as const;
const signer = 'a'.repeat(64);
const fingerprint = `SHA256:${'A'.repeat(43)}`;
const players = vi.hoisted(() => ({
  mounted: 0,
  retired: 0,
  expected: [] as { producer: string; allowUntrusted: boolean }[],
}));
vi.mock('../src/artifacts/ArtifactCatalog', () => ({
  ArtifactCatalog: ({
    onSelect,
    disabled,
    active,
  }: {
    onSelect(value: ArtifactRequest): void;
    disabled: boolean;
    active: boolean;
  }) =>
    createElement(
      'button',
      {
        type: 'button',
        disabled,
        'data-catalog-active': active,
        onClick: () =>
          onSelect({
            kind: 'recording',
            auditlog: 'default',
            id: '34e34ab8-7457-4d88-a5e4-c57791775c3a',
          }),
      },
      'Open fixture recording',
    ),
}));
vi.mock('../src/artifacts/AuditCatalog', () => ({
  AuditCatalog: ({
    onSelect,
    disabled,
  }: {
    onSelect(value: ArtifactRequest): void;
    disabled: boolean;
  }) =>
    createElement(
      'button',
      { type: 'button', disabled, onClick: () => onSelect({ kind: 'audit', auditlog: 'default' }) },
      'Open fixture audit',
    ),
}));
vi.mock('../src/artifacts/RecordingPlayer', async () => {
  const { createElement, useEffect } = await import('react');
  return {
    RecordingPlayer: ({
      autoPrepare,
      disabled,
      expected,
    }: {
      autoPrepare: boolean;
      disabled: boolean;
      expected: { producer: string; allowUntrusted: boolean };
    }) => {
      useEffect(() => {
        players.mounted++;
        players.expected.push(expected);
        return () => {
          players.retired++;
        };
      }, [expected]);
      return createElement('section', {
        'aria-label': 'Fixture player',
        'data-auto-prepare': autoPrepare,
        'data-disabled': disabled,
      });
    },
  };
});
vi.mock('../src/artifacts/protection', () => ({ inspectProtection: vi.fn() }));
vi.mock('../src/artifacts/verify', async (original) => ({
  ...(await original<typeof import('../src/artifacts/verify')>()),
  verifyArtifact: vi.fn(),
}));

function access(principal = 'alice') {
  const scope = { origin: 'https://app.example.org', slug: 'admin' };
  return new WebAccess(
    new Http(
      scope,
      vi.fn(async () => new Response(null, { status: 204 })),
    ),
    {
      scope,
      principal,
      expiresAt: '2100-01-01T00:00:00Z',
      environment: 'management',
      terminalAvailable: false,
      accessToken: `bwa1.${'A'.repeat(43)}`,
    },
    null,
  );
}
function image(request: ArtifactRequest): ReceivedArtifact {
  return {
    request,
    transport: 'complete',
    evidence: 'unverified',
    metadata:
      request.kind === 'recording'
        ? {
            Version: 1,
            ID: request.id,
            ProducerID: 'b'.repeat(64),
            Size: 7,
            SHA256: 'c'.repeat(64),
          }
        : {
            Version: 1,
            Name: request.auditlog,
            Producer: 'b'.repeat(64),
            Recipient: fingerprint,
            Files: [],
          },
    files: [
      {
        name: request.kind === 'recording' ? 'recording' : 'head.cbor',
        data: new Blob(['fixture']),
      },
    ],
  };
}
let encrypted = false;
function metadata(request: ArtifactRequest, options: EvidenceOptions): EvidenceMetadata {
  return {
    kind: request.kind,
    validation: options.level,
    trust: options.allowUntrusted ? 'untrusted' : 'pinned',
    producer: options.producer || signer,
    expectedRecipient: encrypted ? fingerprint : '',
    decryption: encrypted
      ? options.level === 'private'
        ? 'authenticated'
        : 'not-checked'
      : 'not-encrypted',
    recordingId: request.kind === 'recording' ? request.id : '',
    auditScope: request.kind === 'audit' ? 'complete' : '',
    records: '1',
    privateRecords: encrypted ? '1' : '0',
    outputFormat: options.export ? (request.kind === 'recording' ? 'cast' : 'jsonl') : '',
  };
}
function result(selected: ReceivedArtifact, options: EvidenceOptions): VerifiedArtifact {
  return {
    request: selected.request,
    provenance: 'bytes-only',
    metadata: metadata(selected.request, options),
    output: !options.export
      ? null
      : new Blob([
          selected.request.kind === 'recording'
            ? 'checked cast'
            : `${JSON.stringify({
                id: 'event-1',
                recordedAt: '2026-11-04T12:00:00Z',
                event: { name: 'session.task.completed', outcome: 'success', flow: 'work' },
              })}\n`,
        ]),
  };
}
const cleanups: (() => void)[] = [];
beforeEach(() => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  encrypted = false;
  players.mounted = 0;
  players.retired = 0;
  players.expected = [];
  vi.spyOn(WebAccess.prototype, 'downloadArtifact').mockImplementation(async (request) =>
    image(request),
  );
  vi.mocked(inspectProtection).mockImplementation(async (selected) =>
    metadata(selected.request, {
      producer: '',
      allowUntrusted: true,
      recipient: '',
      level: 'outer',
      export: false,
      sensitive: false,
      auditScope: selected.request.kind === 'audit' ? 'complete' : '',
    }),
  );
  vi.mocked(verifyArtifact).mockImplementation(async (selected, options, key) => {
    if (options.producer !== '' && options.producer !== signer) {
      throw new EvidenceError('verification');
    }
    if (encrypted && options.level === 'private') {
      const bytes = await key?.file.text();
      if (
        !key ||
        !bytes?.startsWith('GOOD-KEY') ||
        key.passphrase !== (bytes === 'GOOD-KEY-SECOND' ? 'second secret' : 'tab secret')
      ) {
        throw new EvidenceError('key');
      }
    }
    return result(selected, options);
  });
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
async function mount(selected = access()) {
  const container = document.createElement('div');
  container.style.width = '1000px';
  document.body.append(container);
  const root = createRoot(container);
  cleanups.push(() => {
    root.unmount();
    container.remove();
  });
  async function render(
    options: { access?: WebAccess; active?: boolean; remoteDisabled?: boolean } = {},
  ) {
    await act(async () =>
      root.render(createElement(ArtifactPanel, { access: selected, disabled: false, ...options })),
    );
  }
  await render();
  return { container, render };
}
function button(name: string, parent: ParentNode = document) {
  const node = [...parent.querySelectorAll<HTMLButtonElement>('button')].find(
    (node) => node.textContent === name || node.getAttribute('aria-label') === name,
  );
  if (!node) {
    throw new Error(`Missing button ${name}`);
  }
  return node;
}
async function click(node: HTMLElement) {
  await act(async () => node.click());
}
async function options(parent: ParentNode = document) {
  const summary = parent.querySelector<HTMLElement>('details.artifact-verification > summary');
  if (!summary) {
    throw new Error('Missing verification options');
  }
  if (!summary.parentElement?.hasAttribute('open')) {
    await click(summary);
  }
}
async function fill(input: HTMLInputElement, value: string) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
}
async function selectKey(parent: ParentNode, contents = 'GOOD-KEY', password = 'tab secret') {
  const file = parent.querySelector<HTMLInputElement>('input[type="file"]');
  if (!file) {
    throw new Error('Missing key picker');
  }
  const data = new DataTransfer();
  data.items.add(new File([contents], 'local-key.pem'));
  await act(async () => {
    file.files = data.files;
    file.dispatchEvent(new Event('change', { bubbles: true }));
  });
  const pass = parent.querySelector<HTMLInputElement>('[name="evidence-passphrase"]');
  if (!pass) {
    throw new Error('Missing passphrase input');
  }
  await fill(pass, password);
}

describe('usable local evidence without manual protection guesses', () => {
  it('opens only explicitly, detects protection locally, and never treats prefilled header IDs as independent trust', async () => {
    await mount();
    expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
    expect(inspectProtection).not.toHaveBeenCalled();
    await click(button('Open fixture recording'));
    expect(WebAccess.prototype.downloadArtifact).toHaveBeenCalledExactlyOnceWith(
      recording,
      expect.any(AbortSignal),
    );
    expect(inspectProtection).toHaveBeenCalledOnce();
    expect(verifyArtifact).toHaveBeenCalledExactlyOnceWith(
      image(recording),
      expect.objectContaining({
        producer: '',
        allowUntrusted: true,
        recipient: '',
        level: 'private',
        export: true,
      }),
      null,
      expect.any(AbortSignal),
    );
    expect(document.querySelector<HTMLInputElement>('input[maxlength="64"]')?.value).toBe(signer);
    expect(document.querySelector<HTMLInputElement>('input[maxlength="64"]')?.disabled).toBe(true);
    await vi.waitFor(() =>
      expect(document.querySelector('[aria-label="Fixture player"]')).not.toBeNull(),
    );
    expect(players.expected.at(-1)).toEqual({
      id: recording.id,
      producer: '',
      allowUntrusted: true,
    });
    await options();
    const check = document.querySelector<HTMLInputElement>(
      '.artifact-verification input[type="checkbox"]',
    );
    if (!check) {
      throw new Error('Missing identity validation toggle');
    }
    await click(check);
    await click(button(t('artifactCheckAgain')));
    expect(players.expected.at(-1)).toEqual({
      id: recording.id,
      producer: '',
      allowUntrusted: true,
    });
    const pin = document.querySelector<HTMLInputElement>('input[maxlength="64"]');
    if (!pin) {
      throw new Error('Missing selected ID');
    }
    await fill(pin, 'c'.repeat(64));
    await click(button(t('artifactCheckAgain')));
    expect(document.querySelector('[aria-label="Fixture player"]')).toBeNull();
    expect(document.body.textContent).toContain(t('artifactVerificationFailed'));
    await fill(pin, signer);
    await click(button(t('artifactCheckAgain')));
    await vi.waitFor(() =>
      expect(players.expected.at(-1)).toEqual({
        id: recording.id,
        producer: signer,
        allowUntrusted: false,
      }),
    );
  });
  it('keeps the outer page frameless, actions text-sized, and recording metadata structured below the content', async () => {
    const app = await mount();
    await click(button('Open fixture recording'));
    const back = button(t('artifactBackToList'));
    const status = button(t('recordingVerificationDetails'));
    expect(back.parentElement).toBe(status.parentElement);
    expect(back.getBoundingClientRect().width).toBeLessThan(300);
    expect(status.getBoundingClientRect().width).toBeLessThan(350);
    const panel = app.container.querySelector('.artifact-panel');
    expect(panel?.classList.contains('MuiPaper-root')).toBe(false);
    expect(panel?.querySelectorAll('h2')).toHaveLength(0);
    const details = panel?.querySelector('.recording-evidence');
    expect(details?.querySelector('dl')).not.toBeNull();
    expect(details?.closest('details')).toBeNull();
    expect(details?.querySelector('ul')).toBeNull();
    expect(details?.textContent).toContain(t('recordingDetails'));
    await click(status);
    await vi.waitFor(() =>
      expect(document.querySelector('[role="dialog"]')?.textContent).toContain(
        t('artifactSuggestedSigner'),
      ),
    );
  });
  it('retains local verified output through hiding and remote expiry without another download or verification', async () => {
    const app = await mount();
    await click(button('Open fixture recording'));
    await vi.waitFor(() =>
      expect(document.querySelector('[aria-label="Fixture player"]')).not.toBeNull(),
    );
    const calls = vi.mocked(verifyArtifact).mock.calls.length;
    await app.render({ active: false });
    await app.render({ active: true, remoteDisabled: true });
    expect(document.querySelector('[aria-label="Fixture player"]')).not.toBeNull();
    expect(WebAccess.prototype.downloadArtifact).toHaveBeenCalledTimes(1);
    expect(verifyArtifact).toHaveBeenCalledTimes(calls);
    await click(button(t('artifactBackToList')));
    expect(button('Open fixture recording').disabled).toBe(true);
  });
  it('retires old actor output and selected expectations, and cannot adopt a late old download', async () => {
    const app = await mount();
    await click(button('Open fixture recording'));
    await options();
    const toggle = document.querySelector<HTMLInputElement>(
      '.artifact-verification input[type="checkbox"]',
    );
    if (!toggle) {
      throw new Error('Missing toggle');
    }
    await click(toggle);
    const pin = document.querySelector<HTMLInputElement>('input[maxlength="64"]');
    if (!pin) {
      throw new Error('Missing pin');
    }
    await fill(pin, 'c'.repeat(64));
    await app.render({ access: access('bob') });
    expect(document.querySelector('[aria-label="Fixture player"]')).toBeNull();
    expect(document.querySelector('input[maxlength="64"]')).toBeNull();
    const deferred = Promise.withResolvers<ReceivedArtifact>();
    vi.mocked(WebAccess.prototype.downloadArtifact).mockReturnValueOnce(deferred.promise);
    await click(button('Open fixture recording'));
    await app.render({ access: access('carol') });
    const before = vi.mocked(verifyArtifact).mock.calls.length;
    await act(async () => deferred.resolve(image(recording)));
    expect(verifyArtifact).toHaveBeenCalledTimes(before);
    expect(document.querySelector('[aria-label="Fixture player"]')).toBeNull();
  });
});

function SessionHarness({
  owner,
  signal,
  view,
}: {
  owner: WebAccess;
  signal: AbortSignal;
  view: 'recordings' | 'auditlogs';
}) {
  const secrets = useTabArtifactSecrets(owner, signal);
  return createElement(
    ArtifactSecretsContext.Provider,
    { value: secrets },
    ...(['recordings', 'auditlogs'] as const).map((page) =>
      createElement(
        'div',
        { key: page, hidden: view !== page, 'data-artifact-view': page },
        createElement(ArtifactPanel, {
          access: owner,
          disabled: false,
          active: view === page,
          view: page,
        }),
      ),
    ),
  );
}
it('remembers only a successfully decrypted key across Recording/Audit pages, honors replacement, and clears the scope on tab close under StrictMode', async () => {
  encrypted = true;
  const owner = access();
  const controller = new AbortController();
  const host = document.createElement('div');
  host.style.width = '1000px';
  document.body.append(host);
  const root = createRoot(host);
  cleanups.push(() => {
    root.unmount();
    host.remove();
  });
  const render = async (view: 'recordings' | 'auditlogs') =>
    act(async () =>
      root.render(
        createElement(
          StrictMode,
          null,
          createElement(SessionHarness, { owner, signal: controller.signal, view }),
        ),
      ),
    );
  await render('recordings');
  const recordings = host.querySelector<HTMLElement>('[data-artifact-view="recordings"]');
  const audit = host.querySelector<HTMLElement>('[data-artifact-view="auditlogs"]');
  if (!recordings || !audit) {
    throw new Error('Missing separate owned pages');
  }
  await click(button('Open fixture recording', recordings));
  expect(verifyArtifact).not.toHaveBeenCalled();
  await selectKey(recordings, 'GOOD-KEY', 'wrong');
  await click(button(t('artifactUnlock'), recordings));
  await vi.waitFor(() => expect(recordings.textContent).toContain(t('artifactKeyFailed')));
  expect(recordings.querySelector<HTMLInputElement>('input[type="file"]')?.files).toHaveLength(1);
  await fill(
    recordings.querySelector<HTMLInputElement>('[name="evidence-passphrase"]') as HTMLInputElement,
    'tab secret',
  );
  await click(button(t('artifactUnlock'), recordings));
  await vi.waitFor(() =>
    expect(recordings.querySelector('[aria-label="Fixture player"]')).not.toBeNull(),
  );
  await render('auditlogs');
  await click(button('Open fixture audit', audit));
  await vi.waitFor(() => expect(audit.textContent).toContain('session.task.completed'));
  expect(audit.querySelector('input[type="file"]')).toBeNull();
  expect(vi.mocked(verifyArtifact).mock.calls.at(-1)?.[2]?.passphrase).toBe('tab secret');
  await render('recordings');
  await options(recordings);
  await click(button(t('artifactReplaceKey'), recordings));
  await selectKey(recordings, 'WRONG-KEY', 'wrong');
  await click(button(t('artifactUnlock'), recordings));
  await vi.waitFor(() => expect(recordings.textContent).toContain(t('artifactKeyFailed')));
  const beforeRetry = vi.mocked(verifyArtifact).mock.calls.length;
  await click(button(t('artifactUnlock'), recordings));
  await vi.waitFor(() => expect(verifyArtifact).toHaveBeenCalledTimes(beforeRetry + 1));
  await vi.waitFor(() => expect(recordings.textContent).toContain(t('artifactKeyFailed')));
  expect(await vi.mocked(verifyArtifact).mock.calls.at(-1)?.[2]?.file.text()).toBe('WRONG-KEY');
  await selectKey(recordings, 'GOOD-KEY-SECOND', 'second secret');
  await click(button(t('artifactUnlock'), recordings));
  await vi.waitFor(() =>
    expect(recordings.querySelector('[aria-label="Fixture player"]')).not.toBeNull(),
  );
  const beforeReopen = vi.mocked(verifyArtifact).mock.calls.length;
  await click(button(t('artifactBackToList'), recordings));
  await click(button('Open fixture recording', recordings));
  await vi.waitFor(() => expect(verifyArtifact).toHaveBeenCalledTimes(beforeReopen + 1));
  await vi.waitFor(() =>
    expect(vi.mocked(verifyArtifact).mock.calls.at(-1)?.[2]?.passphrase).toBe('second secret'),
  );
  expect(verifyArtifact).toHaveBeenCalledTimes(beforeReopen + 1);
  await vi.waitFor(() =>
    expect(recordings.querySelector('[aria-label="Fixture player"]')).not.toBeNull(),
  );
  await act(async () => controller.abort());
  await click(button(t('artifactBackToList'), recordings));
  const count = vi.mocked(verifyArtifact).mock.calls.length;
  await click(button('Open fixture recording', recordings));
  expect(recordings.querySelector('input[type="file"]')).not.toBeNull();
  expect(verifyArtifact).toHaveBeenCalledTimes(count);
});
