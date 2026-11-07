import { act, createElement, type ReactNode, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { page as browserPage, userEvent } from 'vitest/browser';
import { ArtifactCatalog } from '../src/artifacts/ArtifactCatalog';
import { ArtifactPanel } from '../src/artifacts/ArtifactPanel';
import type { AuditOverviewPage } from '../src/management/audit-overview';
import type { RecordingSummary } from '../src/management/protocol';
import { WebAccess } from '../src/remember/client';
import { Http } from '../src/remember/http';
import { RememberMeError } from '../src/remember/protocol';
import { ManagementNavigationContext } from '../src/ui/management-navigation';
import { t } from '../src/ui/messages';
import { profileResetEvent } from '../src/ui/profile-reset';
import '../src/ui/app.css';

const id = '34e34ab8-7457-4d88-a5e4-c57791775c3a';
const source = { name: 'default', enabled: true, recordingEnabled: true, encrypted: false };
const event = {
  key: `1:0:${id}`,
  id,
  recordedAt: '2026-11-05T00:00:00Z',
  event: { name: 'session.task.completed', outcome: 'success' },
};
const overview: AuditOverviewPage = {
  items: [event],
  next: '',
  skipped: 0,
  total: 1,
  source: {
    auditlog: 'default',
    encrypted: false,
    sensitive: false,
    verification: 'server-overview',
  },
};
const recording: RecordingSummary = {
  auditlog: 'default',
  id,
  producerId: 'a'.repeat(64),
  format: 'bcast/v1',
  status: 'completed',
  startedAt: '2026-11-05T00:00:00Z',
  endedAt: '2026-11-05T00:00:01Z',
  containerBytes: 1024,
  chunkCount: 1,
  encrypted: false,
  verificationScope: 'full',
  flow: 'docker',
};
const cleanups: (() => void)[] = [];
let restoreViewport: [number, number] | null = null;
beforeEach(() => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  vi.spyOn(WebAccess.prototype, 'managementAuditlogs').mockResolvedValue({
    items: [source],
    next: '',
    skipped: 0,
  });
  vi.spyOn(WebAccess.prototype, 'managementAuditEvents').mockResolvedValue(overview);
  vi.spyOn(WebAccess.prototype, 'managementRecordings').mockResolvedValue({
    items: [recording],
    next: '',
    skipped: 0,
    total: 1,
  });
  vi.spyOn(WebAccess.prototype, 'downloadArtifact');
  vi.spyOn(WebAccess.prototype, 'managementVerifyRecordings');
});
afterEach(async () => {
  await act(async () => {
    for (const cleanup of cleanups.splice(0)) {
      cleanup();
    }
  });
  vi.restoreAllMocks();
  if (restoreViewport) {
    await browserPage.viewport(...restoreViewport);
    restoreViewport = null;
  }
  vi.unstubAllGlobals();
});
function access() {
  const scope = { origin: 'https://app.example.org', slug: 'Work' };
  return new WebAccess(
    new Http(scope, vi.fn()),
    {
      scope,
      principal: 'alice',
      expiresAt: '2100-01-01T00:00:00Z',
      environment: 'management',
      terminalAvailable: false,
      accessToken: `bwa1.${'A'.repeat(43)}`,
    },
    null,
  );
}
async function mount(node: ReactNode) {
  const host = document.createElement('div');
  host.style.width = '1300px';
  document.body.append(host);
  const root = createRoot(host);
  cleanups.push(() => {
    root.unmount();
    host.remove();
  });
  await act(async () => root.render(node));
  return host;
}
function button(host: ParentNode, name: string) {
  const result = [...host.querySelectorAll<HTMLButtonElement>('button')].find(
    (node) =>
      !node.closest('[hidden]') &&
      (node.textContent === name || node.getAttribute('aria-label') === name),
  );
  if (!result) {
    throw new Error(`Missing ${name}`);
  }
  return result;
}
const click = async (node: HTMLElement) => act(async () => node.click());
const eventRows = (host: HTMLElement) =>
  host.querySelectorAll(`[role="grid"][aria-label="${t('auditEvents')}"] [role="row"][data-id]`);
async function confirmVerify(host: HTMLElement) {
  const start = button(host, t('verifyOpen'));
  expect(start.closest('[role="toolbar"]')).not.toBeNull();
  await click(start);
  const dialog = [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].find(
    (node) => !node.closest('[aria-hidden="true"]'),
  );
  if (!dialog) {
    throw new Error('Missing scope confirmation');
  }
  expect(dialog.textContent).toContain('default');
  await click(button(dialog, t('verifyStart')));
  await vi.waitFor(() => expect(dialog.closest('[aria-hidden="true"]')).not.toBeNull());
}

it('opens audit events as a server overview without downloading or automatically verifying the journal', async () => {
  const host = await mount(
    createElement(ArtifactPanel, {
      access: access(),
      view: 'auditlogs',
      active: true,
      disabled: false,
    }),
  );
  await vi.waitFor(() => expect(button(host, 'Open audit log default').disabled).toBe(false));
  await click(button(host, 'Open audit log default'));
  await vi.waitFor(() => expect(eventRows(host)).toHaveLength(1));
  expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledOnce();
  expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
  expect(WebAccess.prototype.managementVerifyRecordings).not.toHaveBeenCalled();
  expect(host.textContent).not.toContain(t('auditOverviewWarning'));
  expect(host.textContent).not.toContain('Integrity OK');
  await click(button(host, `${t('auditEventDetails')} ${id}`));
  await vi.waitFor(() => expect(host.querySelector('[aria-current="page"]')?.textContent).toBe(id));
  expect(host.querySelector(`[aria-label="${t('auditEventDetails')}"]`)?.textContent).toContain(
    t('detailsTitle'),
  );
  expect(host.querySelector(`[aria-label="${t('auditOverviewBack')}"]`)).toBeNull();
  expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledTimes(2);
  expect(vi.mocked(WebAccess.prototype.managementAuditEvents).mock.calls[1]?.[1]).toMatchObject({
    id,
  });
  expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
  await click(button(host, 'default'));
  await vi.waitFor(() => expect(eventRows(host)).toHaveLength(1));
  expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledTimes(2);
});

it('starts a local full audit check only after confirmation and keeps the operational overview usable while it runs', async () => {
  let artifactSignal: AbortSignal | undefined;
  vi.mocked(WebAccess.prototype.downloadArtifact).mockImplementation((_request, signal) => {
    artifactSignal = signal;
    return new Promise((_resolve, reject) => {
      signal?.addEventListener('abort', () => reject(new RememberMeError('cancelled')), {
        once: true,
      });
    });
  });
  const host = await mount(
    createElement(ArtifactPanel, {
      access: access(),
      view: 'auditlogs',
      active: true,
      disabled: false,
    }),
  );
  await click(button(host, 'Open audit log default'));
  await vi.waitFor(() => expect(eventRows(host)).toHaveLength(1));
  await confirmVerify(host);
  await vi.waitFor(() => expect(WebAccess.prototype.downloadArtifact).toHaveBeenCalledOnce());
  expect(vi.mocked(WebAccess.prototype.downloadArtifact).mock.calls[0]?.[0]).toEqual({
    kind: 'audit',
    auditlog: 'default',
  });
  expect(
    host.querySelector('[data-testid="GridLoadingOverlay"]')?.closest('[role="grid"]'),
  ).not.toBeNull();
  expect(
    host.querySelector('[data-testid="CancelIcon"]')?.closest('[role="toolbar"]'),
  ).not.toBeNull();
  expect(host.querySelector(`[aria-label="${t('auditOverviewMode')}"]`)).toBeNull();
  expect(artifactSignal?.aborted).toBe(false);
  const before = vi.mocked(WebAccess.prototype.managementAuditEvents).mock.calls.length;
  expect(button(host, t('auditRefreshEvents')).disabled).toBe(true);
  expect(host.querySelector<HTMLElement>('.MuiDataGrid-virtualScrollerRenderZone')?.inert).toBe(
    true,
  );
  expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledTimes(before);
  expect(artifactSignal?.aborted).toBe(false);
  await click(button(host, t('verifyAllCancel')));
  await vi.waitFor(() => expect(artifactSignal?.aborted).toBe(true));
  expect(WebAccess.prototype.downloadArtifact).toHaveBeenCalledOnce();
});

it('locks recording paging during explicit verification and restores it after cancellation', async () => {
  restoreViewport = [window.innerWidth, window.innerHeight];
  await browserPage.viewport(1440, 900);
  vi.mocked(WebAccess.prototype.managementRecordings)
    .mockResolvedValueOnce({ items: [recording], next: 'bmp1.next', skipped: 0, total: 21 })
    .mockResolvedValue({ items: [recording], next: '', skipped: 0, total: 21 });
  let signal: AbortSignal | undefined;
  vi.mocked(WebAccess.prototype.managementVerifyRecordings).mockImplementation(
    (_source, stopped) => {
      signal = stopped;
      return new Promise((_resolve, reject) => {
        stopped?.addEventListener('abort', () => reject(new RememberMeError('cancelled')), {
          once: true,
        });
      });
    },
  );
  const onSelect = vi.fn();
  const host = await mount(
    createElement(ArtifactCatalog, {
      access: access(),
      active: true,
      disabled: false,
      onSelect,
    }),
  );
  await vi.waitFor(() => expect(button(host, `Open recording ${id}`).disabled).toBe(false));
  expect(WebAccess.prototype.managementVerifyRecordings).not.toHaveBeenCalled();
  await confirmVerify(host);
  await vi.waitFor(() =>
    expect(WebAccess.prototype.managementVerifyRecordings).toHaveBeenCalledOnce(),
  );
  expect(vi.mocked(WebAccess.prototype.managementVerifyRecordings).mock.calls[0]?.[0]).toBe(
    'default',
  );
  expect(button(host, 'Go to next page').disabled).toBe(true);
  expect(host.querySelector<HTMLElement>('.MuiDataGrid-virtualScrollerRenderZone')?.inert).toBe(
    true,
  );
  expect(signal?.aborted).toBe(false);
  await click(button(host, t('verifyAllCancel')));
  await vi.waitFor(() => expect(signal?.aborted).toBe(true));
  await act(async () => userEvent.click(button(host, 'Go to next page')));
  await vi.waitFor(() => expect(WebAccess.prototype.managementRecordings).toHaveBeenCalledTimes(2));
  expect(vi.mocked(WebAccess.prototype.managementRecordings).mock.calls[1]?.[1]).toMatchObject({
    after: 'bmp1.next',
  });
  expect(signal?.aborted).toBe(true);
  await vi.waitFor(() => expect(button(host, t('recordingRefresh')).disabled).toBe(false));
  const grid = browserPage.getByRole('grid', {
    name: `${t('recordingList')} · default`,
    exact: true,
  });
  await act(async () => userEvent.click(grid.getByRole('gridcell', { name: id, exact: true })));
  expect(onSelect).toHaveBeenCalledOnce();
  expect(signal?.aborted).toBe(true);
});

it.each(['success', 'failure'] as const)(
  'shows the %s recording verification result only as an icon and opens compact details on click',
  async (outcome) => {
    if (outcome === 'success') {
      vi.mocked(WebAccess.prototype.managementVerifyRecordings).mockResolvedValue({
        checked: 3,
        full: 2,
        outer: 1,
        auditlog: 'default',
        independent: false,
      });
    } else {
      vi.mocked(WebAccess.prototype.managementVerifyRecordings).mockRejectedValue(
        new RememberMeError('denied'),
      );
    }
    const host = await mount(
      createElement(ArtifactCatalog, {
        access: access(),
        active: true,
        disabled: false,
        onSelect: vi.fn(),
      }),
    );
    await vi.waitFor(() => expect(button(host, t('verifyOpen')).disabled).toBe(false));
    await confirmVerify(host);
    await vi.waitFor(() =>
      expect(host.querySelector(`[data-verification-result="${outcome}"]`)).not.toBeNull(),
    );
    const result = button(host, t('recordingVerificationDetails'));
    expect(result.textContent).toBe('');
    expect(result.closest('[role="toolbar"]')).not.toBeNull();
    expect(host.querySelector('[role="toolbar"]')?.textContent).not.toContain(
      t('verifyAllServerDone'),
    );
    await click(result);
    const dialog = [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].find((node) =>
      node.checkVisibility({ visibilityProperty: true }),
    );
    expect(dialog?.querySelector('dl')?.textContent).toContain('default');
    expect(dialog?.textContent).toContain(t('verificationServerReported'));
    if (!dialog) {
      throw new Error('Missing result dialog');
    }
    await click(button(dialog, t('close')));
    await click(button(host, t('directServerData')));
    expect(host.querySelector('[data-verification-result]')).toBeNull();
    expect(WebAccess.prototype.managementVerifyRecordings).toHaveBeenCalledOnce();
  },
);

it('keeps encrypted overview fields private and erases the owned view on profile reset without starting a new read', async () => {
  vi.mocked(WebAccess.prototype.managementAuditEvents).mockResolvedValue({
    ...overview,
    source: { ...overview.source, encrypted: true },
  });
  const host = await mount(
    createElement(ArtifactPanel, {
      access: access(),
      view: 'auditlogs',
      active: true,
      disabled: false,
    }),
  );
  await click(button(host, 'Open audit log default'));
  await vi.waitFor(() => expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledOnce());
  expect(host.textContent).not.toContain(t('auditOverviewEncrypted'));
  expect(host.querySelector<HTMLInputElement>('input[type="checkbox"]')).toBeNull();
  await click(button(host, t('adminGridShowDetails')));
  expect(
    vi
      .mocked(WebAccess.prototype.managementAuditEvents)
      .mock.calls.every((call) => call[1]?.sensitive === false),
  ).toBe(true);
  expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
  await act(async () => window.dispatchEvent(new Event(profileResetEvent)));
  expect(host.textContent).toContain(t('auditOverviewForgotten'));
  expect(host.textContent).not.toContain(event.event.name);
  expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledOnce();
});

function ReauthenticationHarness({
  owned,
  controls,
}: {
  owned: WebAccess;
  controls: { deactivate(): void; reactivate(): void };
}) {
  const [active, setActive] = useState(true);
  controls.deactivate = () => setActive(false);
  controls.reactivate = () => setActive(true);
  return createElement(
    ManagementNavigationContext.Provider,
    {
      value: active
        ? {
            location: { managementFlow: 'management', page: 'auditlogs', auditlog: 'default' },
            navigate: vi.fn(),
          }
        : null,
    },
    createElement(ArtifactPanel, { access: owned, view: 'auditlogs', active, disabled: false }),
  );
}

it('retains the actor-owned audit route and local view when reauthentication temporarily removes navigation context', async () => {
  const owned = access();
  const controls = { deactivate: () => {}, reactivate: () => {} };
  let signal: AbortSignal | undefined;
  vi.mocked(WebAccess.prototype.downloadArtifact).mockImplementation((_request, stopped) => {
    signal = stopped;
    return new Promise((_resolve, reject) =>
      stopped?.addEventListener('abort', () => reject(new RememberMeError('cancelled')), {
        once: true,
      }),
    );
  });
  const host = await mount(createElement(ReauthenticationHarness, { owned, controls }));
  await confirmVerify(host);
  await vi.waitFor(() => expect(WebAccess.prototype.downloadArtifact).toHaveBeenCalledOnce());
  const local = host.querySelector(`[aria-label="${t('auditLocalRegion')}"]`);
  expect(local).not.toBeNull();
  await act(async () => controls.deactivate());
  await vi.waitFor(() => expect(signal?.aborted).toBe(true));
  expect(local?.isConnected).toBe(true);
  await act(async () => controls.reactivate());
  expect(host.querySelector(`[aria-label="${t('auditLocalRegion')}"]`)).toBe(local);
  expect(WebAccess.prototype.downloadArtifact).toHaveBeenCalledOnce();
});
