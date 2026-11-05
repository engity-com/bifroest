import { act, createElement, StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ArtifactCatalog } from '../src/artifacts/ArtifactCatalog';
import type { ArtifactRequest } from '../src/artifacts/protocol';
import type { AuditlogSummary, Page, RecordingSummary } from '../src/management/protocol';
import { WebAccess } from '../src/remember/client';
import { Http } from '../src/remember/http';
import { t } from '../src/ui/messages';
import { closeNativeFilter, nativeColumnFilter } from './native-grid-filter-ui';
import '../src/ui/app.css';

const source: AuditlogSummary = {
  name: 'default',
  enabled: true,
  recordingEnabled: true,
  encrypted: false,
};
const row: RecordingSummary = {
  auditlog: 'default',
  id: '34e34ab8-7457-4d88-a5e4-c57791775c3a',
  producerId: 'a'.repeat(64),
  format: 'bcast/v1',
  status: 'completed',
  startedAt: '2026-11-03T12:00:00Z',
  endedAt: '2026-11-03T12:00:05Z',
  containerBytes: 1024,
  chunkCount: 1,
  encrypted: false,
  verificationScope: 'full',
  flow: 'ops',
  user: 'alice',
  target: 'service-account',
};
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
const cleanups: (() => void)[] = [];
beforeEach(() => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  vi.spyOn(WebAccess.prototype, 'managementAuditlogs').mockResolvedValue({
    items: [source],
    next: '',
    skipped: 0,
  });
  vi.spyOn(WebAccess.prototype, 'managementRecordings').mockResolvedValue({
    items: [row],
    next: '',
    skipped: 0,
  });
  vi.spyOn(WebAccess.prototype, 'downloadArtifact');
});
afterEach(async () => {
  await act(async () => {
    for (const cleanup of cleanups.splice(0)) {
      cleanup();
    }
  });
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
async function mount(initial = access(), active = true, strict = false) {
  const element = document.createElement('div');
  element.style.width = '1200px';
  document.body.append(element);
  const root = createRoot(element);
  const selected = vi.fn<(request: ArtifactRequest, summary?: RecordingSummary) => void>();
  const render = async (
    options: {
      access?: WebAccess;
      active?: boolean;
      disabled?: boolean;
      selected?: ArtifactRequest;
    } = {},
  ) => {
    await act(async () => {
      const content = createElement(ArtifactCatalog, {
        access: initial,
        active,
        disabled: false,
        onSelect: selected,
        ...options,
      });
      root.render(strict ? createElement(StrictMode, null, content) : content);
    });
  };
  cleanups.push(() => {
    root.unmount();
    element.remove();
  });
  await render();
  return { element, render, selected };
}
function button(name: string) {
  const result = [...document.querySelectorAll<HTMLButtonElement>('button')].find(
    (node) => node.textContent === name || node.getAttribute('aria-label') === name,
  );
  if (!result) {
    throw new Error(`Missing button ${name}`);
  }
  return result;
}
async function click(element: HTMLElement) {
  await act(async () => element.click());
}
function hasNamedCombobox(name: string): boolean {
  return [...document.querySelectorAll('[role="combobox"]')].some((node) =>
    (node.getAttribute('aria-labelledby') ?? '')
      .split(/\s+/u)
      .some((id) => document.getElementById(id)?.textContent === name),
  );
}

describe('finding and opening recordings without API choreography', () => {
  it('does not duplicate protected metadata reads during StrictMode effect replay', async () => {
    await mount(access(), true, true);
    expect(WebAccess.prototype.managementAuditlogs).toHaveBeenCalledTimes(1);
    expect(WebAccess.prototype.managementRecordings).toHaveBeenCalledTimes(1);
    expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
  });
  it('loads only the first visible view, skips a pointless single-source chooser and never downloads on discovery', async () => {
    const app = await mount(access(), false);
    expect(WebAccess.prototype.managementAuditlogs).not.toHaveBeenCalled();
    await app.render({ active: true });
    expect(WebAccess.prototype.managementAuditlogs).toHaveBeenCalledTimes(1);
    expect(WebAccess.prototype.managementRecordings).toHaveBeenCalledExactlyOnceWith(
      'default',
      expect.objectContaining({
        sort: 'started-desc',
        filter: null,
        after: '',
      }),
      expect.any(AbortSignal),
    );
    expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
    expect(document.body.textContent).toContain('alice');
    expect(document.body.textContent).toContain('ops');
    expect(document.body.textContent).toContain('service-account');
    expect(document.body.textContent).not.toContain(row.producerId);
    expect(hasNamedCombobox(t('recordingSource'))).toBe(false);
    await app.render({ active: false });
    await app.render({ active: true });
    expect(WebAccess.prototype.managementAuditlogs).toHaveBeenCalledTimes(1);
    expect(WebAccess.prototype.managementRecordings).toHaveBeenCalledTimes(1);
  });
  it('opens the exact row as one explicit intent and marks its selected identity', async () => {
    const app = await mount();
    await click(button(`${t('recordingOpen')} ${row.id}`));
    expect(app.selected).toHaveBeenCalledExactlyOnceWith(
      { kind: 'recording', auditlog: row.auditlog, id: row.id },
      row,
    );
    await app.render({ selected: { kind: 'recording', auditlog: row.auditlog, id: row.id } });
    expect(button(`${t('recordingOpen')} ${row.id}`).getAttribute('aria-current')).toBe('true');
    expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
  });

  it('does not put an unlabelled missing target below an existing requesting user', async () => {
    const withoutTarget = { ...row };
    Reflect.deleteProperty(withoutTarget, 'target');
    vi.mocked(WebAccess.prototype.managementRecordings).mockResolvedValue({
      items: [withoutTarget],
      next: '',
      skipped: 0,
    });
    await mount();
    expect(document.querySelector('[role="gridcell"][data-field="user"]')?.textContent).toBe(
      'alice',
    );
  });
  it('shows a long recording duration in minutes instead of a large seconds count', async () => {
    vi.mocked(WebAccess.prototype.managementRecordings).mockResolvedValue({
      items: [{ ...row, endedAt: '2026-11-03T12:30:12Z' }],
      next: '',
      skipped: 0,
    });
    await mount();
    expect(document.querySelector('[role="gridcell"][data-field="duration"]')?.textContent).toBe(
      '30 min 12 s',
    );
  });

  it('submits the native column predicate and retains it through real cursor page changes', async () => {
    vi.mocked(WebAccess.prototype.managementRecordings).mockResolvedValue({
      items: [row],
      next: 'bmp1.next',
      skipped: 0,
    });
    const app = await mount();
    expect(WebAccess.prototype.managementRecordings).toHaveBeenCalledTimes(1);
    await nativeColumnFilter(app.element, 'User', 'alice');
    await vi.waitFor(() =>
      expect(
        vi.mocked(WebAccess.prototype.managementRecordings).mock.calls.at(-1)?.[1],
      ).toMatchObject({
        filter: { field: 'user', operator: 'contains', value: 'alice' },
        after: '',
      }),
    );
    await closeNativeFilter(app.element);
    await click(button('Go to next page'));
    expect(
      vi.mocked(WebAccess.prototype.managementRecordings).mock.calls.at(-1)?.[1],
    ).toMatchObject({
      filter: { field: 'user', operator: 'contains', value: 'alice' },
      after: 'bmp1.next',
    });
    await click(button('Go to previous page'));
    expect(
      vi.mocked(WebAccess.prototype.managementRecordings).mock.calls.at(-1)?.[1],
    ).toMatchObject({ filter: { field: 'user', operator: 'contains', value: 'alice' }, after: '' });
  });
  it('does not choose a source or download implicitly when the source inventory has another page', async () => {
    vi.mocked(WebAccess.prototype.managementAuditlogs).mockResolvedValue({
      items: [source],
      next: 'bmp1.sources',
      skipped: 0,
    });
    await mount();
    expect(WebAccess.prototype.managementRecordings).not.toHaveBeenCalled();
    expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
    expect(hasNamedCombobox(t('recordingSource'))).toBe(true);
    expect(button(t('recordingSourcesMore'))).toBeDefined();
  });

  it('selects the only recording source when it becomes known on the final source page', async () => {
    vi.mocked(WebAccess.prototype.managementAuditlogs)
      .mockResolvedValueOnce({
        items: [{ ...source, name: 'audit-only', recordingEnabled: false }],
        next: 'bmp1.remaining',
        skipped: 0,
      })
      .mockResolvedValueOnce({ items: [source], next: '', skipped: 0 });
    await mount();
    expect(WebAccess.prototype.managementRecordings).not.toHaveBeenCalled();
    await click(button(t('recordingSourcesMore')));
    expect(WebAccess.prototype.managementAuditlogs).toHaveBeenCalledTimes(2);
    expect(WebAccess.prototype.managementRecordings).toHaveBeenCalledExactlyOnceWith(
      'default',
      expect.objectContaining({ sort: 'started-desc', filter: null }),
      expect.any(AbortSignal),
    );
    expect(hasNamedCombobox(t('recordingSource'))).toBe(false);
    expect(button(`${t('recordingOpen')} ${row.id}`)).toBeDefined();
    expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
  });
  it('keeps a failed/cancelled page failed without an automatic retry or partial rows', async () => {
    let release!: (page: Page<RecordingSummary>) => void;
    vi.mocked(WebAccess.prototype.managementRecordings).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    );
    const app = await mount();
    expect(
      document.querySelector(`[role="grid"][aria-label="${t('recordingList')} · default"]`),
    ).toBeNull();
    await click(button(t('artifactCatalogCancel')));
    expect(vi.mocked(WebAccess.prototype.managementRecordings).mock.calls[0]?.[2]?.aborted).toBe(
      true,
    );
    await act(async () => release({ items: [row], next: '', skipped: 0 }));
    await app.render({ active: false });
    await app.render({ active: true });
    expect(
      document.querySelector(`[role="grid"][aria-label="${t('recordingList')} · default"]`),
    ).toBeNull();
    expect(WebAccess.prototype.managementRecordings).toHaveBeenCalledTimes(1);
    expect(document.body.textContent).toContain(t('artifactCatalogCancelled'));
  });
  it('does not publish a late source page under a different actor', async () => {
    let release!: (page: Page<AuditlogSummary>) => void;
    vi.mocked(WebAccess.prototype.managementAuditlogs).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    );
    const app = await mount();
    await app.render({ access: access('bob') });
    await act(async () =>
      release({ items: [{ ...source, name: 'old-actor-private-source' }], next: '', skipped: 0 }),
    );
    expect(document.body.textContent).not.toContain('old-actor-private-source');
    expect(WebAccess.prototype.managementRecordings).toHaveBeenCalledTimes(1);
    expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
  });
});
