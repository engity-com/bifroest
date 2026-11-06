import { act, createElement, useMemo } from 'react';
import { createRoot } from 'react-dom/client';
import { createMemoryRouter, useLocation, useNavigate } from 'react-router';
import { RouterProvider } from 'react-router/dom';
import { afterEach, expect, it, vi } from 'vitest';
import { page as browserPage, userEvent } from 'vitest/browser';
import { ArtifactPanel } from '../src/artifacts/ArtifactPanel';
import { AuditEvents } from '../src/artifacts/AuditEvents';
import type { EvidenceMetadata } from '../src/artifacts/evidence-protocol';
import { inspectProtection } from '../src/artifacts/protection';
import type { ReceivedArtifact } from '../src/artifacts/protocol';
import { verifyArtifact } from '../src/artifacts/verify';
import { SessionActionConfirmation } from '../src/management/action';
import { ManagementPanel } from '../src/management/ManagementPanel';
import type { WebAccess } from '../src/remember';
import { RememberMeError } from '../src/remember';
import { managementPath, parseManagementLocation } from '../src/ui/management-location';
import { ManagementNavigationContext } from '../src/ui/management-navigation';
import { t } from '../src/ui/messages';
import '../src/ui/app.css';
import { nativeColumnFilter } from './native-grid-filter-ui';

vi.mock('../src/artifacts/protection', () => ({ inspectProtection: vi.fn() }));
vi.mock('../src/artifacts/verify', async (original) => ({
  ...(await original<typeof import('../src/artifacts/verify')>()),
  verifyArtifact: vi.fn(),
}));
vi.mock('../src/artifacts/RecordingPlayer', () => ({
  RecordingPlayer: () =>
    createElement('div', { 'aria-label': 'Routed player' }, 'Verified Recording'),
}));
const scope = { origin: 'https://app.example.org', slug: 'Admin' };
const id = '34e34ab8-7457-4d88-a5e4-c57791775c3a';
const session = {
  flow: 'Docker',
  id,
  state: 'authorized' as const,
  user: 'alice',
  remote: 'alice@127.0.0.1',
  createdAt: '2026-01-01T00:00:00Z',
  owner: null,
};
const noLock = () => {};
function fixture() {
  const api = {
    snapshot: () => ({
      scope,
      flow: { name: 'admin', title: 'Management' },
      principal: 'alice',
      environment: 'management',
      expiresAt: '2100-01-01T00:00:00Z',
    }),
    status: () => 'active',
    subscribeStatus: () => () => {},
    managementSessions: vi.fn(async (_options: unknown, _signal?: AbortSignal) => ({
      items: [session],
      next: '',
      skipped: 0,
    })),
    managementSession: vi.fn(async (_flow: string, _id: string, _signal?: AbortSignal) => session),
    managementFlows: vi.fn(async () => ({ items: [], next: '', skipped: 0 })),
    managementVersion: vi.fn(),
    managementAuditlogs: vi.fn(async () => ({
      items: [{ name: 'default', enabled: true, recordingEnabled: true, encrypted: false }],
      next: '',
      skipped: 0,
    })),
    managementRecordings: vi.fn<WebAccess['managementRecordings']>(async () => ({
      items: [],
      next: '',
      skipped: 0,
    })),
    downloadArtifact: vi.fn<WebAccess['downloadArtifact']>(),
    prepareSessionAction: vi.fn(
      async (action: 'disconnect' | 'dispose', flow: string, id: string, _signal?: AbortSignal) =>
        new SessionActionConfirmation(
          {
            action,
            target: { flow, id, details: session },
            expiresAt: new Date(Date.now() + 60_000).toISOString(),
          },
          async () => ({ action, flow, id }),
          async () => {},
        ),
    ),
  };
  return { api, access: api as unknown as WebAccess };
}
function Scene({
  access,
  kind,
  source,
}: {
  access: WebAccess;
  kind: 'sessions' | 'recordings' | 'audit';
  source: Blob;
}) {
  const location = useLocation();
  const navigate = useNavigate();
  const route = useMemo(() => parseManagementLocation(scope, location), [location]);
  if (!route) {
    throw new Error('Invalid routed fixture');
  }
  return createElement(
    ManagementNavigationContext.Provider,
    {
      value: {
        location: route,
        navigate: (target, replace) => {
          void navigate(managementPath(scope, target), { replace: replace ?? false });
        },
      },
    },
    kind === 'sessions'
      ? createElement(ManagementPanel, {
          access,
          active: true,
          disabled: false,
          onActionLock: noLock,
          view: 'sessions',
        })
      : kind === 'recordings'
        ? createElement(ArtifactPanel, {
            access,
            active: true,
            disabled: false,
            view: 'recordings',
          })
        : createElement(AuditEvents, { source, active: true }),
  );
}
const cleanups: (() => void)[] = [];
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
async function mount(
  path: string,
  kind: 'sessions' | 'recordings' | 'audit',
  access: WebAccess,
  source = new Blob(),
) {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  const host = document.createElement('div');
  host.style.width = '1300px';
  document.body.append(host);
  const root = createRoot(host);
  const router = createMemoryRouter(
    [{ path: '*', element: createElement(Scene, { access, kind, source }) }],
    { initialEntries: [path] },
  );
  cleanups.push(() => {
    root.unmount();
    router.dispose();
    host.remove();
  });
  await act(async () => root.render(createElement(RouterProvider, { router })));
  return { host, router };
}
function button(host: ParentNode, label: string) {
  const result = [...host.querySelectorAll<HTMLButtonElement>('button')].find(
    (node) =>
      !node.closest('[hidden]') &&
      (node.getAttribute('aria-label') === label || node.textContent === label),
  );
  if (!result) {
    throw new Error(`Missing button ${label}`);
  }
  return result;
}
const click = async (node: HTMLElement) => act(async () => node.click());

it('binds a sessions URI to the literal flow and opens/closes details through the router without rereading the retained list', async () => {
  const { access, api } = fixture();
  const { host, router } = await mount('/Admin/admin/sessions/Docker', 'sessions', access);
  await vi.waitFor(() => expect(api.managementSessions).toHaveBeenCalledTimes(1));
  expect(api.managementSessions.mock.calls[0]?.[0]).toMatchObject({
    flow: 'Docker',
    filter: { field: 'flow', operator: 'equals', value: 'Docker' },
  });
  expect(api.managementFlows).not.toHaveBeenCalled();
  const grid = host.querySelector('[role="grid"][aria-label="Live session metadata"]');
  await click(button(host, `Session details ${id}`));
  await vi.waitFor(() =>
    expect(router.state.location.pathname).toBe(`/Admin/admin/sessions/Docker/${id}`),
  );
  await vi.waitFor(() => expect(host.querySelector('.session-details')).not.toBeNull());
  expect(api.managementSession).toHaveBeenCalledExactlyOnceWith(
    'Docker',
    id,
    expect.any(AbortSignal),
  );
  await click(button(host, 'Close'));
  await vi.waitFor(() =>
    expect(router.state.location.pathname).toBe('/Admin/admin/sessions/Docker'),
  );
  expect(api.managementSessions).toHaveBeenCalledTimes(1);
  expect(host.querySelector('[role="grid"][aria-label="Live session metadata"]')).toBe(grid);
});
it('opens a cold session detail URI without listing sessions or unrelated overview/version data', async () => {
  const { access, api } = fixture();
  const { host } = await mount(`/Admin/admin/sessions/Docker/${id}`, 'sessions', access);
  await vi.waitFor(() => expect(host.querySelector('.session-details')).not.toBeNull());
  expect(api.managementSession).toHaveBeenCalledOnce();
  expect(api.managementSessions).not.toHaveBeenCalled();
  expect(api.managementFlows).not.toHaveBeenCalled();
  expect(api.managementVersion).not.toHaveBeenCalled();
});
it('keeps the session pin and its portalled Select open through a real opening pointer gesture', async () => {
  const { access, api } = fixture();
  await mount('/Admin/admin/sessions', 'sessions', access);
  await vi.waitFor(() => expect(api.managementSessions).toHaveBeenCalledOnce());
  await act(async () =>
    userEvent.click(browserPage.getByRole('button', { name: 'Open by ID', exact: true })),
  );
  const dialog = browserPage.getByRole('dialog', { name: 'Open by ID', exact: true });
  await act(async () =>
    userEvent.click(dialog.getByRole('combobox', { name: 'Session action', exact: true })),
  );
  await act(async () =>
    userEvent.click(
      browserPage.getByRole('option', { name: 'Disconnect connections', exact: true }),
    ),
  );
  await vi.waitFor(() => expect(document.querySelector('.MuiMenu-root')).toBeNull());
  expect(
    dialog.getByRole('combobox', { name: 'Session action', exact: true }).element().textContent,
  ).toContain('Disconnect connections');
  expect(
    browserPage
      .getByRole('button', { name: 'Open by ID', exact: true })
      .element()
      .getAttribute('aria-expanded'),
  ).toBe('true');
  expect(api.managementSession).not.toHaveBeenCalled();
  await act(async () => {
    for (const [label, value] of [
      ['Target flow', 'Docker'],
      ['Target session ID', id],
    ] as const) {
      const input = dialog
        .getByRole('textbox', { name: label, exact: true })
        .element() as HTMLInputElement;
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(input, value);
      input.dispatchEvent(new Event('input', { bubbles: true }));
    }
  });
  await act(async () => userEvent.click(dialog.getByRole('button', { name: 'Go', exact: true })));
  await vi.waitFor(() =>
    expect(api.prepareSessionAction).toHaveBeenCalledExactlyOnceWith(
      'disconnect',
      'Docker',
      id,
      expect.any(AbortSignal),
    ),
  );
  expect(
    browserPage
      .getByRole('button', { name: 'Open by ID', exact: true, includeHidden: true })
      .element()
      .getAttribute('aria-expanded'),
  ).toBe('false');
  expect(document.querySelector('[role="dialog"]')?.textContent).toContain(
    'Confirm session action',
  );
});
it('moves a confirmed action back to its list URI without replaying details or automatically refreshing invalidated metadata', async () => {
  const { access, api } = fixture();
  const { host, router } = await mount(`/Admin/admin/sessions/Docker/${id}`, 'sessions', access);
  await vi.waitFor(() => expect(host.querySelector('.session-details')).not.toBeNull());
  await click(button(host, 'Disconnect connections'));
  const input = document.querySelector<HTMLInputElement>('[role="dialog"] input');
  if (!input) {
    throw new Error('Missing exact target confirmation');
  }
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(
      input,
      `Docker/${id}`,
    );
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await click(button(document, 'Confirm session action'));
  await vi.waitFor(() =>
    expect(router.state.location.pathname).toBe('/Admin/admin/sessions/Docker'),
  );
  expect(api.managementSession).toHaveBeenCalledOnce();
  expect(api.managementSessions).not.toHaveBeenCalled();
  expect(host.querySelector('.session-details')).toBeNull();
  expect(button(host, 'Refresh sessions').disabled).toBe(false);
});
it('removes the URI flow segment when the real native filter stops being exact, and removes the literal API selector too', async () => {
  const { access, api } = fixture();
  const { host, router } = await mount('/Admin/admin/sessions/Docker', 'sessions', access);
  await vi.waitFor(() => expect(api.managementSessions).toHaveBeenCalledOnce());
  await vi.waitFor(() => expect(button(host, 'Refresh sessions').disabled).toBe(false));
  await nativeColumnFilter(host, 'Flow', 'Docker', 'contains');
  await vi.waitFor(() => expect(router.state.location.pathname).toBe('/Admin/admin/sessions'));
  await vi.waitFor(() => expect(api.managementSessions).toHaveBeenCalledTimes(2));
  expect(api.managementSessions.mock.calls.at(-1)?.[0]).toMatchObject({
    filter: { field: 'flow', operator: 'contains', value: 'Docker' },
  });
  expect(api.managementSessions.mock.calls.at(-1)?.[0]).not.toHaveProperty('flow');
});
it('opens a qualified Recording URI as one explicit transfer and validates the verified flow before showing playback', async () => {
  const { access, api } = fixture();
  const image: ReceivedArtifact = {
    request: { kind: 'recording', auditlog: 'default', id },
    transport: 'complete',
    evidence: 'unverified',
    metadata: { Version: 1, ID: id, ProducerID: 'a'.repeat(64), Size: 7, SHA256: 'b'.repeat(64) },
    files: [{ name: 'recording', data: new Blob(['fixture']) }],
  };
  api.downloadArtifact.mockResolvedValue(image);
  const metadata: EvidenceMetadata = {
    kind: 'recording',
    validation: 'private',
    trust: 'untrusted',
    producer: 'a'.repeat(64),
    expectedRecipient: '',
    decryption: 'not-encrypted',
    recordingId: id,
    auditScope: '',
    records: '0',
    privateRecords: '0',
    outputFormat: 'cast',
  };
  vi.mocked(inspectProtection).mockResolvedValue({
    ...metadata,
    validation: 'outer',
    outputFormat: '',
  });
  vi.mocked(verifyArtifact).mockResolvedValue({
    request: image.request,
    provenance: 'bytes-only',
    metadata,
    output: new Blob([`{}\n# bifroest:metadata:v1 {"recordingId":"${id}","flow":"Docker"}\n`]),
  });
  const { host, router } = await mount(
    `/Admin/admin/recordings/Docker/${id}?auditlog=default`,
    'recordings',
    access,
  );
  await vi.waitFor(() => expect(host.querySelector('[aria-label="Routed player"]')).not.toBeNull());
  expect(api.downloadArtifact).toHaveBeenCalledExactlyOnceWith(
    image.request,
    expect.any(AbortSignal),
  );
  expect(api.managementAuditlogs).not.toHaveBeenCalled();
  expect(api.managementRecordings).not.toHaveBeenCalled();
  await act(async () =>
    router.navigate(`/Admin/admin/recordings/Other?recording=${id}&auditlog=default`),
  );
  await vi.waitFor(() => expect(host.textContent).toContain(t('artifactVerificationFailed')));
  expect(host.querySelector('[aria-label="Routed player"]')).toBeNull();
  expect(api.downloadArtifact).toHaveBeenCalledOnce();
  expect(verifyArtifact).toHaveBeenCalledTimes(2);
  expect(router.state.location.pathname).toBe('/Admin/admin/recordings/Other');
  expect(router.state.location.search).toContain(`recording=${id}`);
});
it('retires an in-flight Recording route on Back and can open another explicit route without a stale download or stuck busy lease', async () => {
  const { access, api } = fixture();
  const pending = Promise.withResolvers<ReceivedArtifact>();
  api.downloadArtifact.mockImplementationOnce(() => pending.promise);
  const { host, router } = await mount(
    `/Admin/admin/recordings/Docker/${id}?auditlog=default`,
    'recordings',
    access,
  );
  await vi.waitFor(() => expect(api.downloadArtifact).toHaveBeenCalledOnce());
  const signal = api.downloadArtifact.mock.calls[0]?.[1] as AbortSignal;
  await act(async () => router.navigate('/Admin/admin/recordings?auditlog=default'));
  await vi.waitFor(() => expect(signal.aborted).toBe(true));
  expect(host.querySelector('[aria-label="Routed player"]')).toBeNull();
  const next = '70d5159d-a0e4-46ca-b011-c4f831f4ade0';
  api.downloadArtifact.mockRejectedValue(new Error('controlled next transfer denial'));
  await act(async () => router.navigate(`/Admin/admin/recordings/Docker/${next}?auditlog=default`));
  await vi.waitFor(() => expect(api.downloadArtifact).toHaveBeenCalledTimes(2));
  expect(api.downloadArtifact.mock.calls.at(-1)?.[0]).toEqual({
    kind: 'recording',
    auditlog: 'default',
    id: next,
  });
  expect(host.querySelector('[aria-label="Routed player"]')).toBeNull();
  await act(async () => pending.reject(new Error('controlled retired transfer')));
  expect(api.downloadArtifact).toHaveBeenCalledTimes(2);
});
it('loads a newly selected explicit source even when no source was previously selected', async () => {
  const { access, api } = fixture();
  api.managementAuditlogs.mockResolvedValue({
    items: [
      { name: 'default', enabled: true, recordingEnabled: true, encrypted: false },
      { name: 'other', enabled: true, recordingEnabled: true, encrypted: false },
    ],
    next: '',
    skipped: 0,
  });
  const { router } = await mount('/Admin/admin/recordings', 'recordings', access);
  await vi.waitFor(() => expect(api.managementAuditlogs).toHaveBeenCalledOnce());
  expect(api.managementRecordings).not.toHaveBeenCalled();
  await act(async () => router.navigate('/Admin/admin/recordings?auditlog=other'));
  await vi.waitFor(() =>
    expect(api.managementRecordings).toHaveBeenCalledExactlyOnceWith(
      'other',
      expect.objectContaining({ query: '', filter: null }),
      expect.any(AbortSignal),
    ),
  );
  expect(api.downloadArtifact).not.toHaveBeenCalled();
});
it('does not automatically retry a denied sole-source Recording read after source discovery', async () => {
  const { access, api } = fixture();
  api.managementRecordings.mockRejectedValue(new Error('controlled recording read denial'));
  const { host } = await mount('/Admin/admin/recordings', 'recordings', access);
  await vi.waitFor(() => expect(host.textContent).toContain(t('recordingReadFailed')));
  expect(api.managementRecordings).toHaveBeenCalledOnce();
});
it('shows retained verification progress and reads again only after explicit Refresh', async () => {
  const { access, api } = fixture();
  api.managementRecordings.mockRejectedValueOnce(new RememberMeError('catalog-incomplete'));
  const { host } = await mount('/Admin/admin/recordings', 'recordings', access);
  await vi.waitFor(() => expect(host.textContent).toContain(t('recordingCatalogWarming')));
  await vi.waitFor(() => expect(button(host, 'Refresh recordings').disabled).toBe(false));
  expect(api.managementRecordings).toHaveBeenCalledOnce();
  expect(host.querySelectorAll('[role="row"][data-id]').length).toBe(0);
  await click(button(host, 'Refresh recordings'));
  await vi.waitFor(() => expect(api.managementRecordings).toHaveBeenCalledTimes(2));
  await vi.waitFor(() => expect(host.textContent).not.toContain(t('recordingCatalogWarming')));
  expect(api.downloadArtifact).not.toHaveBeenCalled();
});
it('reopens the same encrypted Recording through the router with a fresh owned transfer and a visible local-key form', async () => {
  const { access, api } = fixture();
  const image: ReceivedArtifact = {
    request: { kind: 'recording', auditlog: 'default', id },
    transport: 'complete',
    evidence: 'unverified',
    metadata: { Version: 1, ID: id, ProducerID: 'a'.repeat(64), Size: 7, SHA256: 'b'.repeat(64) },
    files: [{ name: 'recording', data: new Blob(['fixture']) }],
  };
  api.downloadArtifact.mockResolvedValue(image);
  vi.mocked(inspectProtection).mockResolvedValue({
    kind: 'recording',
    validation: 'outer',
    trust: 'untrusted',
    producer: 'a'.repeat(64),
    expectedRecipient: `SHA256:${'A'.repeat(43)}`,
    decryption: 'not-checked',
    recordingId: id,
    auditScope: '',
    records: '0',
    privateRecords: '0',
    outputFormat: '',
  });
  const path = `/Admin/admin/recordings?auditlog=default&recording=${id}`;
  const { host, router } = await mount(path, 'recordings', access);
  await vi.waitFor(() =>
    expect(host.querySelector('.artifact-key input[type="file"]')).not.toBeNull(),
  );
  await click(button(host, t('artifactBackToList')));
  await vi.waitFor(() => expect(router.state.location.search).toBe('?auditlog=default'));
  await vi.waitFor(() => expect(host.querySelector('.artifact-key')).toBeNull());
  await act(async () => router.navigate(path));
  await vi.waitFor(() => expect(api.downloadArtifact).toHaveBeenCalledTimes(2));
  await vi.waitFor(() =>
    expect(host.querySelector('.artifact-key input[type="file"]')).not.toBeNull(),
  );
  expect(verifyArtifact).not.toHaveBeenCalled();
});
it('resolves an audit event outside the first page and replaces an ID-only shortcut with its verified flow path', async () => {
  const { access } = fixture();
  const rows = Array.from({ length: 45 }, (_, index) => ({
    id: index === 35 ? id : `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
    recordedAt: new Date(Date.UTC(2026, 0, 1, 0, index)).toISOString(),
    event: {
      name: `session.event.${index}`,
      flow: index === 35 ? 'Docker' : 'Other',
      outcome: 'success',
    },
  }));
  const source = new Blob(rows.map((row) => `${JSON.stringify(row)}\n`));
  const { host, router } = await mount(
    `/Admin/admin/auditlogs/default?event=${id}`,
    'audit',
    access,
    source,
  );
  await vi.waitFor(() =>
    expect(router.state.location.pathname).toBe(`/Admin/admin/auditlogs/default/Docker/${id}`),
  );
  expect(router.state.location.search).toBe('');
  await vi.waitFor(() =>
    expect(host.querySelector('.audit-event-details')?.textContent).toContain('session.event.35'),
  );
  expect(host.querySelector('[role="dialog"]')).toBeNull();
  await act(async () => router.navigate(`/Admin/admin/auditlogs/default/Other?event=${id}`));
  await vi.waitFor(() => expect(host.textContent).toContain(t('auditEventsFailed')));
  expect(host.querySelector('.audit-event-details')).toBeNull();
  expect(router.state.location.pathname).toBe('/Admin/admin/auditlogs/default/Other');
  expect(router.state.location.search).toBe(`?event=${id}`);
});
