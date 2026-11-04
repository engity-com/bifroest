import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ArtifactPanel } from '../src/artifacts/ArtifactPanel';
import type { EvidenceOptions, VerifiedArtifact } from '../src/artifacts/evidence-protocol';
import type { ArtifactRequest, ReceivedArtifact } from '../src/artifacts/protocol';
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
const players = vi.hoisted(() => ({ mounted: 0, retired: 0 }));
vi.mock('../src/artifacts/ArtifactCatalog', async () => {
  const { createElement } = await import('react');
  return {
    ArtifactCatalog: ({
      onSelect,
      disabled,
      active,
    }: {
      onSelect: (value: ArtifactRequest) => void;
      disabled: boolean;
      active: boolean;
    }) =>
      createElement(
        'button',
        {
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
  };
});
vi.mock('../src/artifacts/RecordingPlayer', async () => {
  const { createElement, useEffect } = await import('react');
  return {
    RecordingPlayer: ({ autoPrepare, disabled }: { autoPrepare: boolean; disabled: boolean }) => {
      useEffect(() => {
        players.mounted++;
        return () => {
          players.retired++;
        };
      }, []);
      return createElement('section', {
        'aria-label': 'Fixture player',
        'data-auto-prepare': autoPrepare,
        'data-disabled': disabled,
      });
    },
  };
});
vi.mock('../src/artifacts/verify', async (original) => ({
  ...(await original<typeof import('../src/artifacts/verify')>()),
  verifyArtifact: vi.fn(),
}));

function access(principal = 'alice') {
  const scope = { origin: 'https://app.example.org', slug: 'admin' };
  return new WebAccess(
    new Http(scope, vi.fn()),
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
const received: ReceivedArtifact = {
  request: recording,
  transport: 'complete',
  evidence: 'unverified',
  metadata: {
    Version: 1,
    ID: recording.id,
    ProducerID: 'b'.repeat(64),
    Size: 7,
    SHA256: 'c'.repeat(64),
  },
  files: [{ name: 'recording', data: new Blob(['fixture']) }],
};
function verified(selected: ReceivedArtifact, options: EvidenceOptions): VerifiedArtifact {
  return {
    request: selected.request,
    provenance: 'bytes-only',
    output: new Blob(['checked cast']),
    metadata: {
      kind: 'recording',
      validation: options.level,
      trust: options.allowUntrusted ? 'untrusted' : 'pinned',
      producer: options.producer || 'a'.repeat(64),
      expectedRecipient: options.recipient,
      decryption: 'not-encrypted',
      recordingId: recording.id,
      auditScope: '',
      records: '1',
      privateRecords: '1',
      outputFormat: 'cast',
    },
  };
}
const cleanups: (() => void)[] = [];
beforeEach(() => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  players.mounted = 0;
  players.retired = 0;
  vi.spyOn(WebAccess.prototype, 'downloadArtifact').mockResolvedValue(received);
  vi.mocked(verifyArtifact).mockImplementation(async (selected, options) =>
    verified(selected, options),
  );
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
  document.body.append(container);
  const root = createRoot(container);
  const render = async (
    options: { access?: WebAccess; remoteDisabled?: boolean; active?: boolean } = {},
  ) => {
    await act(async () =>
      root.render(createElement(ArtifactPanel, { access: selected, disabled: false, ...options })),
    );
  };
  cleanups.push(() => {
    root.unmount();
    container.remove();
  });
  await render();
  return { container, render };
}
function button(name: string) {
  const element = [...document.querySelectorAll('button')].find(
    (button) => button.textContent === name,
  );
  if (!element) {
    throw new Error(`Missing button ${name}`);
  }
  return element;
}
async function click(element: HTMLElement) {
  await act(async () => element.click());
}
async function chooseProtection() {
  const checkbox = document.querySelector<HTMLInputElement>(
    '.artifact-verification input[type="checkbox"]',
  );
  if (!checkbox) {
    throw new Error('Missing trust decision');
  }
  await click(checkbox);
  const select = document.querySelector<HTMLElement>('.artifact-verification [role="combobox"]');
  if (!select) {
    throw new Error('Missing expected protection');
  }
  await act(async () =>
    select.dispatchEvent(new MouseEvent('mousedown', { button: 0, bubbles: true })),
  );
  const clear = [...document.querySelectorAll<HTMLElement>('[role="option"]')].find(
    (node) => node.textContent === t('artifactClear'),
  );
  if (!clear) {
    throw new Error('Missing unencrypted choice');
  }
  await click(clear);
}

describe('opening an existing recording as a user task', () => {
  it('keeps actions content-sized on one left-aligned row and exposes evidence in a persistent card', async () => {
    const app = await mount();
    app.container.style.width = '800px';
    await click(button('Open fixture recording'));
    const check = button(t('artifactVerify'));
    const close = button(t('artifactClearTab'));
    expect(check.parentElement).toBe(close.parentElement);
    expect(getComputedStyle(check.parentElement as HTMLElement).flexWrap).toBe('nowrap');
    expect(check.getBoundingClientRect().top).toBe(close.getBoundingClientRect().top);
    expect(check.getBoundingClientRect().width).toBeLessThan(300);
    await chooseProtection();
    await click(check);
    const actions = [
      button(t('artifactSaveExport')),
      button(t('recordingChangeVerification')),
      button(t('artifactClearTab')),
    ];
    for (const action of actions) {
      expect(action.parentElement).toBe(actions[0]?.parentElement);
      expect(action.getBoundingClientRect().top).toBe(actions[0]?.getBoundingClientRect().top);
      expect(action.getBoundingClientRect().width).toBeLessThan(300);
    }
    const card = document.querySelector('.recording-evidence');
    expect(card?.closest('details')).toBeNull();
    expect(card?.textContent).toContain(t('recordingVerificationDetails'));
    expect(card?.textContent).toContain(t('artifactHints'));
    expect(card?.querySelector('dl')).not.toBeNull();
    expect(
      document.querySelector(`nav[aria-label="${t('adminBreadcrumbs')}"] [aria-current="page"]`),
    ).not.toBeNull();
  });
  it('opens only on an explicit row action, never copies server hints into independent expectations, and prepares playback after full verification', async () => {
    await mount();
    expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
    await click(button('Open fixture recording'));
    expect(WebAccess.prototype.downloadArtifact).toHaveBeenCalledTimes(1);
    expect(WebAccess.prototype.downloadArtifact).toHaveBeenCalledWith(
      recording,
      expect.any(AbortSignal),
    );
    expect(document.querySelector<HTMLInputElement>('input[maxlength="64"]')?.value).toBe('');
    expect(button(t('artifactVerify')).disabled).toBe(true);
    expect(verifyArtifact).not.toHaveBeenCalled();
    await chooseProtection();
    expect(button(t('artifactVerify')).disabled).toBe(false);
    await click(button(t('artifactVerify')));
    expect(verifyArtifact).toHaveBeenCalledExactlyOnceWith(
      received,
      expect.objectContaining({
        producer: '',
        allowUntrusted: true,
        recipient: '',
        level: 'private',
        export: true,
        sensitive: false,
        auditScope: '',
      }),
      null,
      expect.any(AbortSignal),
    );
    expect(
      document.querySelector('[aria-label="Fixture player"]')?.getAttribute('data-auto-prepare'),
    ).toBe('true');
    expect(document.querySelector('form.artifact-verification')).toBeNull();
    expect(document.body.textContent).toContain(t('recordingIdentityUnknown'));
  });

  it('retains local verified output across hidden-view changes and remote expiry without re-downloading or re-verifying', async () => {
    const app = await mount();
    await click(button('Open fixture recording'));
    await chooseProtection();
    await click(button(t('artifactVerify')));
    await app.render({ active: false });
    await app.render({ active: true, remoteDisabled: true });
    expect(players.mounted).toBe(1);
    expect(players.retired).toBe(0);
    expect(
      document.querySelector('[aria-label="Fixture player"]')?.getAttribute('data-disabled'),
    ).toBe('false');
    expect(WebAccess.prototype.downloadArtifact).toHaveBeenCalledTimes(1);
    expect(verifyArtifact).toHaveBeenCalledTimes(1);
    await click(button(t('artifactTitle')));
    expect(button('Open fixture recording').disabled).toBe(true);
    expect(WebAccess.prototype.downloadArtifact).toHaveBeenCalledTimes(1);
  });

  it('retires the old actor’s local data and independently selected expectations on an access change', async () => {
    const app = await mount();
    await click(button('Open fixture recording'));
    await chooseProtection();
    await click(button(t('artifactVerify')));
    await app.render({ access: access('bob') });
    expect(players.retired).toBe(1);
    expect(document.querySelector('[aria-label="Fixture player"]')).toBeNull();
    expect(document.querySelector('form.artifact-verification')).toBeNull();
    expect(WebAccess.prototype.downloadArtifact).toHaveBeenCalledTimes(1);
    await click(button('Open fixture recording'));
    expect(document.querySelector<HTMLInputElement>('input[type="checkbox"]')?.checked).toBe(false);
    expect(button(t('artifactVerify')).disabled).toBe(true);
  });

  it('does not adopt a late download after ownership changed or restart it automatically', async () => {
    let release!: (value: ReceivedArtifact) => void;
    vi.mocked(WebAccess.prototype.downloadArtifact).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    );
    const app = await mount();
    await click(button('Open fixture recording'));
    await app.render({ access: access('bob') });
    await act(async () => release(received));
    expect(document.querySelector('form.artifact-verification')).toBeNull();
    expect(WebAccess.prototype.downloadArtifact).toHaveBeenCalledTimes(1);
    expect(verifyArtifact).not.toHaveBeenCalled();
  });
});
