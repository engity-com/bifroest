import { act, createElement, type ReactNode, useMemo } from 'react';
import { createRoot } from 'react-dom/client';
import { createMemoryRouter, useLocation, useNavigate } from 'react-router';
import { RouterProvider } from 'react-router/dom';
import { afterEach, expect, it, vi } from 'vitest';
import { page as browserPage, userEvent } from 'vitest/browser';
import { managementPath, parseManagementLocation } from '../src/application/management-location';
import { ArtifactPanel } from '../src/artifacts/ArtifactPanel';
import { AuditEvents } from '../src/artifacts/AuditEvents';
import type { EvidenceMetadata } from '../src/artifacts/evidence-protocol';
import { openRecording } from '../src/artifacts/open-recording';
import { inspectProtection } from '../src/artifacts/protection';
import type { ReceivedArtifact } from '../src/artifacts/protocol';
import { verifyArtifact } from '../src/artifacts/verify';
import { SessionActionConfirmation } from '../src/management/action';
import { ManagementPanel } from '../src/management/ManagementPanel';
import type { RecordingSummary } from '../src/management/protocol';
import type { WebAccess } from '../src/remember';
import { RememberMeError } from '../src/remember';
import { ManagementWorkspace } from '../src/ui/ManagementWorkspace';
import { ManagementNavigationContext } from '../src/ui/management-navigation';
import { t } from '../src/ui/messages';
import { openedFixture } from './open-recording-fixture';
import { recordingRuntimeFixture } from './recording-runtime-fixture';
import '../src/ui/app.css';
import { nativeColumnFilter } from './native-grid-filter-ui';

vi.mock('../src/artifacts/protection', () => ({ inspectProtection: vi.fn() }));
vi.mock('../src/artifacts/open-recording', () => ({
    openRecording: vi.fn(),
    openRecordingWithWorker: vi.fn(),
}));
vi.mock('../src/artifacts/verify', async (original) => ({
    ...(await original<typeof import('../src/artifacts/verify')>()),
    verifyArtifact: vi.fn(),
    createRecordingRuntime: vi.fn(async (_source: string, _id: string, signal: AbortSignal) =>
        recordingRuntimeFixture(openRecording, verifyArtifact, signal),
    ),
}));
vi.mock('../src/artifacts/RecordingPlayer', () => ({
    RecordingPlayer: ({ verificationControls }: { verificationControls?: ReactNode }) =>
        createElement('div', { 'aria-label': 'Routed player' }, verificationControls),
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
    vi.mocked(openRecording).mockImplementation(async (image) =>
        openedFixture(image.request.kind === 'recording' ? image.request.id : '', 'a'.repeat(64), {
            flow: 'Docker',
        }),
    );
    const api = {
        snapshot: () => ({
            scope,
            flow: { name: 'admin', title: 'Management' },
            principal: 'alice',
            environment: 'management',
            expiresAt: '2100-01-01T00:00:00Z',
        }),
        status: () => 'active',
        managementStatus: () => 'active',
        subscribeStatus: () => () => {},
        openManagement: vi.fn(() => ({ disconnect: vi.fn() })),
        managementSessions: vi.fn(async (_options: unknown, _signal?: AbortSignal) => ({
            items: [session],
            next: '',
            skipped: 0,
        })),
        managementSession: vi.fn(
            async (_flow: string, _id: string, _signal?: AbortSignal) => session,
        ),
        managementFlows: vi.fn<WebAccess['managementFlows']>(async () => ({
            items: [],
            next: '',
            skipped: 0,
        })),
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
        managementAuditEvents: vi.fn<WebAccess['managementAuditEvents']>(async (source) => ({
            items: [
                {
                    key: `1:0:${id}`,
                    id,
                    recordedAt: '2026-11-05T00:00:00Z',
                    event: { name: 'session.task.completed', outcome: 'success' },
                },
            ],
            next: '',
            skipped: 0,
            total: 1,
            source: {
                auditlog: source,
                encrypted: false,
                sensitive: false,
                verification: 'server-overview',
            },
        })),
        downloadArtifact: vi.fn<WebAccess['downloadArtifact']>(),
        prepareSessionAction: vi.fn(
            async (
                action: 'disconnect' | 'dispose',
                flow: string,
                id: string,
                _signal?: AbortSignal,
            ) =>
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
    kind: 'sessions' | 'recordings' | 'audit' | 'workspace';
    source: Blob;
}) {
    const location = useLocation();
    const navigate = useNavigate();
    const route = useMemo(() => parseManagementLocation(scope, location), [location]);
    const cancellation = useMemo(() => new AbortController(), []);
    if (!route) {
        throw new Error('Invalid routed fixture');
    }
    if (kind === 'workspace') {
        return createElement(ManagementWorkspace, {
            access,
            owner: 1,
            active: true,
            disabled: false,
            onActionLock: noLock,
            onReauthenticate: noLock,
            signal: cancellation.signal,
            location: route,
            onNavigate: (_owner, target, replace) => {
                void navigate(managementPath(scope, target), { replace: replace ?? false });
            },
        });
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
              : createElement(AuditEvents, { source, active: true, privateFieldsKnown: true }),
    );
}
const cleanups: (() => void)[] = [];
let restoreViewport: [number, number] | null = null;
afterEach(async () => {
    await act(async () => {
        for (const cleanup of cleanups.splice(0)) {
            cleanup();
        }
    });
    vi.restoreAllMocks();
    vi.clearAllMocks();
    vi.unstubAllGlobals();
    if (restoreViewport) {
        await browserPage.viewport(...restoreViewport);
        restoreViewport = null;
    }
});
async function mount(
    path: string,
    kind: 'sessions' | 'recordings' | 'audit' | 'workspace',
    access: WebAccess,
    source = new Blob(),
) {
    vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
    const host = document.createElement('div');
    host.style.width = '1300px';
    host.style.height = '900px';
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
    const result = [...host.querySelectorAll<HTMLButtonElement>('button,a[href]')].find(
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
async function verifyRecording(host: HTMLElement) {
    await vi.waitFor(() => expect(button(host, t('verifyOpen')).disabled).toBe(false));
    await click(button(host, t('verifyOpen')));
    const dialog = [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].find((node) =>
        node.checkVisibility({ visibilityProperty: true }),
    );
    if (!dialog) {
        throw new Error('Missing verification options');
    }
    await click(button(dialog, t('verifyStart')));
}

it('uses screenshot_monitor and fact_check consistently for Overview actions and side navigation', async () => {
    restoreViewport = [window.innerWidth, window.innerHeight];
    await browserPage.viewport(1440, 900);
    const { access, api } = fixture();
    api.managementFlows.mockResolvedValue({
        items: [
            { name: 'docker', auditlog: 'default', authorization: 'simple', environment: 'docker' },
        ],
        next: '',
        skipped: 0,
    });
    const { host } = await mount('/Admin/admin', 'workspace', access);
    // Actions can be outside the horizontally virtualized viewport. Exercise
    // the real scroll instead of assuming all columns are mounted at CI's width.
    await vi.waitFor(async () => {
        await act(async () => {});
        expect(host.querySelector('[role="row"][data-id="docker"]')).not.toBeNull();
    });
    await act(async () => {
        const scroller = host.querySelector('.MuiDataGrid-virtualScroller');
        scroller?.scrollTo({ left: scroller.scrollWidth });
    });
    await vi.waitFor(() => expect(button(host, 'Recordings docker').disabled).toBe(false));
    expect(
        button(host, 'Recordings docker').querySelector('[data-testid="ScreenshotMonitorIcon"]'),
    ).not.toBeNull();
    expect(
        button(host, 'Audit logs docker').querySelector('[data-testid="FactCheckIcon"]'),
    ).not.toBeNull();
    expect(
        [...host.querySelectorAll(`nav[aria-label="${t('workspaceNavigation')}"] a[href]`)].some(
            (node) => node.textContent === 'Recordings',
        ),
    ).toBe(false);
    expect(
        button(host, 'Audit logs').querySelector('[data-testid="FactCheckIcon"]'),
    ).not.toBeNull();
});

it('uses one audit-source entry page, explicit Events/Recordings branches, and same-source toolbar switches without dropdowns or redundant reads', async () => {
    const { api, access } = recordingCatalogFixture();
    const { host, router } = await mount('/Admin/admin/auditlogs', 'workspace', access);
    await vi.waitFor(() => expect(button(host, 'Open audit log default').disabled).toBe(false));
    const navigation = host.querySelector(`nav[aria-label="${t('workspaceNavigation')}"]`);
    expect(navigation?.textContent).not.toContain('Recordings');
    const events = button(host, 'Open audit log default');
    const recordings = button(host, 'Recordings default');
    expect(events.querySelector('[data-testid="FactCheckIcon"]')).not.toBeNull();
    expect(events.querySelector('[data-testid="SearchIcon"]')).toBeNull();
    expect(recordings.querySelector('[data-testid="ScreenshotMonitorIcon"]')).not.toBeNull();
    const actions = events.closest('.actions');
    expect(
        actions?.firstElementChild?.querySelector('[data-testid="FactCheckIcon"]'),
    ).not.toBeNull();
    expect(api.managementRecordings).not.toHaveBeenCalled();
    expect(api.downloadArtifact).not.toHaveBeenCalled();
    await click(events);
    await vi.waitFor(() =>
        expect(router.state.location.pathname).toBe('/Admin/admin/auditlogs/default/events'),
    );
    await vi.waitFor(() => expect(api.managementAuditEvents).toHaveBeenCalledOnce());
    const crumbs = () => host.querySelector('.admin-breadcrumbs')?.textContent;
    expect(crumbs()).toBe('Bifröst/Audit logs/default/Events');
    const recordLink = [
        ...host.querySelectorAll<HTMLAnchorElement>('a[aria-label="Recordings default"]'),
    ].find((node) => !node.closest('[hidden]'));
    if (!recordLink) {
        throw new Error('Missing same-source Recordings toolbar link');
    }
    expect(recordLink.getAttribute('href')).toBe('/#Admin/-/auditlogs/default/recordings');
    const toolbarNames = [
        ...(recordLink.closest('[role="toolbar"]')?.querySelectorAll('button,a') ?? []),
    ].map((node) => node.getAttribute('aria-label'));
    expect(toolbarNames.indexOf('Recordings default') + 1).toBe(
        toolbarNames.indexOf(t('recordingManual')),
    );
    await click(recordLink);
    await vi.waitFor(() => expect(button(host, `Open recording ${id}`).disabled).toBe(false));
    expect(router.state.location.pathname).toBe('/Admin/admin/auditlogs/default/recordings');
    expect(crumbs()).toBe('Bifröst/Audit logs/default/Recordings');
    expect(host.textContent).not.toContain(t('recordingSource'));
    expect(api.managementRecordings).toHaveBeenCalledOnce();
    expect(api.downloadArtifact).not.toHaveBeenCalled();
    const eventLink = [
        ...host.querySelectorAll<HTMLAnchorElement>('a[aria-label="Events default"]'),
    ].find((node) => !node.closest('[hidden]'));
    if (!eventLink) {
        throw new Error('Missing Events toolbar link');
    }
    await click(eventLink);
    await vi.waitFor(() =>
        expect(router.state.location.pathname).toBe('/Admin/admin/auditlogs/default/events'),
    );
    expect(crumbs()).toBe('Bifröst/Audit logs/default/Events');
    expect(api.managementAuditEvents).toHaveBeenCalledOnce();
    await click(button(host, 'Audit logs'));
    await vi.waitFor(() => expect(button(host, 'Recordings default').disabled).toBe(false));
    await click(button(host, 'Recordings default'));
    await vi.waitFor(() =>
        expect(router.state.location.pathname).toBe('/Admin/admin/auditlogs/default/recordings'),
    );
    expect(api.managementRecordings).toHaveBeenCalledOnce();
    expect(api.managementAuditlogs).toHaveBeenCalledOnce();
});

it('shows local audit indexing as cancellable work and releases no events from an unfinished index', async () => {
    const { access, api } = fixture();
    const bytes = new TextEncoder().encode(
        `${JSON.stringify({ id, recordedAt: '2026-11-05T00:00:00Z', event: { name: 'session.task.completed', flow: 'docker' } })}\n`,
    );
    const cancelled = vi.fn();
    let reads = 0;
    class SlowAudit extends Blob {
        override stream(): ReadableStream<Uint8Array<ArrayBuffer>> {
            reads++;
            return reads === 1
                ? new ReadableStream({
                      start(controller) {
                          controller.enqueue(bytes);
                      },
                      cancel: cancelled,
                  })
                : super.stream();
        }
    }
    const source = new SlowAudit([bytes]);
    const { host } = await mount('/Admin/admin/auditlogs/default', 'audit', access, source);
    await vi.waitFor(() => expect(host.textContent).toContain(t('scanIndexing')));
    expect(host.querySelectorAll('[role="row"][data-id]')).toHaveLength(0);
    await click(button(host, t('artifactCatalogCancel')));
    await vi.waitFor(() => expect(host.textContent).toContain(t('artifactCatalogCancelled')));
    expect(cancelled).toHaveBeenCalledOnce();
    expect(host.querySelectorAll('[role="row"][data-id]')).toHaveLength(0);
    expect(reads).toBe(1);
    await click(button(host, t('auditRefreshEvents')));
    await vi.waitFor(() => expect(host.querySelectorAll('[role="row"][data-id]')).toHaveLength(1));
    expect(reads).toBe(2);
    expect(api.downloadArtifact).not.toHaveBeenCalled();
    expect(api.managementRecordings).not.toHaveBeenCalled();
});

function recordingCatalogFixture() {
    const { api, access } = fixture();
    vi.mocked(openRecording).mockImplementation(async (image) =>
        openedFixture(image.request.kind === 'recording' ? image.request.id : '', 'a'.repeat(64), {
            flow: 'docker',
        }),
    );
    const row: RecordingSummary = {
        auditlog: 'default',
        id,
        producerId: 'a'.repeat(64),
        format: 'bcast/v1',
        status: 'completed',
        startedAt: '2026-11-05T00:00:00Z',
        endedAt: '2026-11-05T00:00:01Z',
        containerBytes: 7,
        chunkCount: 1,
        encrypted: false,
        verificationScope: 'full',
        flow: 'docker',
        sessionId: session.id,
        user: 'alice',
    };
    const page = { items: [row], next: '', skipped: 0 };
    api.managementRecordings.mockResolvedValue(page);
    const image: ReceivedArtifact = {
        request: { kind: 'recording', auditlog: 'default', id },
        transport: 'complete',
        evidence: 'unverified',
        metadata: {
            Version: 1,
            ID: id,
            ProducerID: row.producerId,
            Size: 7,
            SHA256: 'b'.repeat(64),
        },
        files: [{ name: 'recording', data: new Blob(['fixture']) }],
    };
    api.downloadArtifact.mockResolvedValue(image);
    const metadata: EvidenceMetadata = {
        kind: 'recording',
        validation: 'private',
        trust: 'untrusted',
        producer: row.producerId,
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
        output: new Blob([`{}\n# bifroest:metadata:v1 {"recordingId":"${id}","flow":"docker"}\n`]),
    });
    return { api, access, page };
}

it('does not pretend an encrypted recording lacks a flow, and broadens the source only after an explicit private-filter action', async () => {
    const { api, access } = fixture();
    api.managementAuditlogs.mockResolvedValue({
        items: [{ name: 'sealed', enabled: true, recordingEnabled: true, encrypted: true }],
        next: '',
        skipped: 0,
    });
    const row: RecordingSummary = {
        auditlog: 'sealed',
        id,
        producerId: 'a'.repeat(64),
        format: 'becast-cbor/v1',
        status: 'completed',
        startedAt: '2026-11-05T00:00:00Z',
        endedAt: '2026-11-05T00:00:01Z',
        containerBytes: 7,
        chunkCount: 1,
        encrypted: true,
        recipientFingerprint: `SHA256:${'A'.repeat(43)}`,
        verificationScope: 'outer',
        metadataUnavailable: true,
    };
    api.managementRecordings.mockImplementation(async (_source, options) => ({
        items: options?.flow || options?.sessionId ? [] : [row],
        next: '',
        skipped: 0,
        total: options?.flow || options?.sessionId ? 0 : 1,
    }));
    api.downloadArtifact.mockResolvedValue({
        request: { kind: 'recording', auditlog: 'sealed', id },
        transport: 'complete',
        evidence: 'unverified',
        metadata: {
            Version: 1,
            ID: id,
            ProducerID: row.producerId,
            Size: 7,
            SHA256: 'b'.repeat(64),
        },
        files: [{ name: 'recording', data: new Blob(['fixture']) }],
    });
    vi.mocked(openRecording).mockImplementation(async () =>
        openedFixture(id, row.producerId, {
            encrypted: true,
            requiresKey: true,
            recipient: row.recipientFingerprint ?? '',
            decryption: 'not-checked',
            flow: '',
            sessionId: '',
        }),
    );
    const { host, router } = await mount(
        '/Admin/admin/recordings/docker-encrypted?auditlog=sealed',
        'recordings',
        access,
    );
    await vi.waitFor(() => expect(api.managementRecordings).toHaveBeenCalled());
    expect(api.managementRecordings.mock.calls[0]?.[1]).toMatchObject({ flow: 'docker-encrypted' });
    await vi.waitFor(() => expect(host.textContent).toContain(t('recordingEncryptedFilter')));
    expect(api.managementRecordings).toHaveBeenCalledOnce();
    expect(api.downloadArtifact).not.toHaveBeenCalled();
    expect(api.managementRecordings.mock.calls[0]?.[1]).toMatchObject({
        flow: 'docker-encrypted',
        filter: { field: 'flow', operator: 'equals', value: 'docker-encrypted' },
    });
    await act(async () => userEvent.click(button(host, t('recordingShowSource'))));
    await vi.waitFor(() => expect(button(host, `Open recording ${id}`).disabled).toBe(false));
    expect(router.state.location.pathname).toBe('/Admin/admin/auditlogs/sealed/recordings');
    expect(router.state.location.search).toBe('');
    expect(api.managementRecordings).toHaveBeenCalledTimes(2);
    expect(api.managementRecordings.mock.calls[1]?.[1]).not.toHaveProperty('flow');
    expect(api.managementRecordings.mock.calls[1]?.[1]).not.toHaveProperty('sessionId');
    expect(api.managementRecordings.mock.calls[1]?.[1]?.filter).toBeNull();
    expect(host.querySelector('[data-field="flow"][role="gridcell"]')?.textContent).toBe(
        t('recordingMetadataProtected'),
    );
    await click(button(host, `Open recording ${id}`));
    await vi.waitFor(() =>
        expect(
            [...document.querySelectorAll('[role="dialog"]')].find((node) =>
                node.checkVisibility({ visibilityProperty: true }),
            )?.textContent,
        ).toContain(t('recordingDecrypt')),
    );
    expect(api.downloadArtifact).toHaveBeenCalledOnce();
    expect(verifyArtifact).not.toHaveBeenCalled();
});

it('does not launch a recording scan after rate-limited source discovery and resumes only on explicit refresh', async () => {
    const { api, access, page } = recordingCatalogFixture();
    api.managementAuditlogs.mockRejectedValueOnce(new RememberMeError('rate-limited'));
    const { host } = await mount('/Admin/admin/recordings?auditlog=default', 'recordings', access);
    await vi.waitFor(() => expect(host.textContent).toContain(t('adminReadRateLimited')));
    expect(api.managementAuditlogs).toHaveBeenCalledOnce();
    expect(api.managementRecordings).not.toHaveBeenCalled();
    expect(api.downloadArtifact).not.toHaveBeenCalled();
    await click(button(host, t('recordingRefresh')));
    await vi.waitFor(() => expect(button(host, `Open recording ${id}`).disabled).toBe(false));
    expect(api.managementAuditlogs).toHaveBeenCalledTimes(2);
    expect(api.managementRecordings).toHaveBeenCalledOnce();
    expect(page.items).toHaveLength(1);
});

it('still permits an exact recording read when the actor cannot enumerate audit sources', async () => {
    const { api, access } = recordingCatalogFixture();
    api.managementAuditlogs.mockRejectedValue(new RememberMeError('denied'));
    const { host } = await mount('/Admin/admin/recordings?auditlog=default', 'recordings', access);
    await vi.waitFor(() => expect(button(host, `Open recording ${id}`).disabled).toBe(false));
    expect(api.managementAuditlogs).toHaveBeenCalledOnce();
    expect(api.managementRecordings).toHaveBeenCalledOnce();
    expect(api.downloadArtifact).not.toHaveBeenCalled();
});

it('returns through the collection breadcrumb to its retained source and explicit flow filter', async () => {
    const { api, access, page } = recordingCatalogFixture();
    api.managementRecordings
        .mockReset()
        .mockResolvedValueOnce(page)
        .mockRejectedValue(new RememberMeError('catalog-incomplete'));
    const { host, router } = await mount(
        '/Admin/admin/auditlogs/default/recordings?flow=docker',
        'workspace',
        access,
    );
    await vi.waitFor(() => expect(api.managementRecordings).toHaveBeenCalledOnce());
    await vi.waitFor(() => expect(button(host, `Open recording ${id}`).disabled).toBe(false));
    const grid = host.querySelector('[role="grid"][aria-label="Recordings · default"]');
    await click(button(host, `Open recording ${id}`));
    await verifyRecording(host);
    await vi.waitFor(() =>
        expect(host.querySelector('[aria-label="Routed player"]')).not.toBeNull(),
    );
    await click(button(host, 'Recordings'));
    await vi.waitFor(() =>
        expect(router.state.location.pathname).toBe('/Admin/admin/auditlogs/default/recordings'),
    );
    await vi.waitFor(() => expect(host.querySelector('[aria-label="Routed player"]')).toBeNull());
    await vi.waitFor(() => expect(button(host, 'Refresh recordings').disabled).toBe(false));
    expect(router.state.location.search).toBe('?flow=docker');
    expect(api.managementRecordings).toHaveBeenCalledOnce();
    expect(host.textContent).not.toContain('Catalog verification needs another read.');
    expect(button(host, `Open recording ${id}`).disabled).toBe(false);
    expect(host.querySelector('[role="grid"][aria-label="Recordings · default"]')).toBe(grid);
    expect(api.downloadArtifact).toHaveBeenCalledOnce();
});

it('loads an explicitly changed flow filter and exposes no earlier rows when that read fails', async () => {
    const { api, access, page } = recordingCatalogFixture();
    api.managementRecordings
        .mockReset()
        .mockResolvedValueOnce(page)
        .mockRejectedValueOnce(new RememberMeError('catalog-incomplete'))
        .mockResolvedValue(page);
    const { host, router } = await mount(
        '/Admin/admin/auditlogs/default/recordings',
        'workspace',
        access,
    );
    await vi.waitFor(() => expect(button(host, `Open recording ${id}`).disabled).toBe(false));
    await click(button(host, `Open recording ${id}`));
    await verifyRecording(host);
    await vi.waitFor(() =>
        expect(host.querySelector('[aria-label="Routed player"]')).not.toBeNull(),
    );
    await act(async () => router.navigate('/Admin/admin/auditlogs/default/recordings?flow=docker'));
    await vi.waitFor(() => expect(host.textContent).toContain(t('recordingReadFailed')));
    expect(router.state.location.pathname).toBe('/Admin/admin/auditlogs/default/recordings');
    expect(api.managementRecordings).toHaveBeenCalledTimes(2);
    expect(host.querySelectorAll('[role="row"][data-id]')).toHaveLength(0);
    await click(button(host, 'Refresh recordings'));
    await vi.waitFor(() => expect(api.managementRecordings).toHaveBeenCalledTimes(3));
    await vi.waitFor(() => expect(button(host, `Open recording ${id}`).disabled).toBe(false));
    expect(host.textContent).not.toContain('Catalog verification needs another read.');
    expect(api.managementRecordings.mock.calls[2]?.[1]).toMatchObject({
        flow: 'docker',
        filter: { field: 'flow', operator: 'equals', value: 'docker' },
    });
});

it('invalidates rows and paging after a failed same-scope refresh instead of displaying an earlier successful page', async () => {
    const { api, access, page } = recordingCatalogFixture();
    api.managementRecordings
        .mockReset()
        .mockResolvedValueOnce({ ...page, next: 'opaque-cursor' })
        .mockRejectedValueOnce(new RememberMeError('catalog-incomplete'))
        .mockResolvedValue(page);
    const { host } = await mount(
        '/Admin/admin/recordings/docker?auditlog=default',
        'recordings',
        access,
    );
    await vi.waitFor(() => expect(button(host, `Open recording ${id}`).disabled).toBe(false));
    const grid = host.querySelector('[role="grid"]');
    await click(button(host, 'Refresh recordings'));
    await vi.waitFor(() => expect(host.textContent).toContain(t('recordingReadFailed')));
    expect(api.managementRecordings).toHaveBeenCalledTimes(2);
    expect(host.querySelectorAll('[role="row"][data-id]')).toHaveLength(0);
    expect(host.querySelector('[aria-label="Go to next page"]')).toBeNull();
    expect(host.querySelector('[role="grid"]')).toBe(grid);
    await click(button(host, 'Refresh recordings'));
    await vi.waitFor(() => expect(button(host, `Open recording ${id}`).disabled).toBe(false));
    expect(api.managementRecordings).toHaveBeenCalledTimes(3);
    expect(api.managementRecordings.mock.calls[2]?.[1]).toMatchObject({
        after: '',
        flow: 'docker',
    });
});

it('repeats only the explicit failed native-filter intent when refreshed after a failure', async () => {
    const { api, access, page } = recordingCatalogFixture();
    api.managementRecordings
        .mockReset()
        .mockResolvedValueOnce(page)
        .mockRejectedValueOnce(new RememberMeError('catalog-incomplete'))
        .mockResolvedValue(page);
    const { host } = await mount('/Admin/admin/recordings?auditlog=default', 'recordings', access);
    await vi.waitFor(() => expect(button(host, `Open recording ${id}`).disabled).toBe(false));
    await nativeColumnFilter(host, 'User', 'alice', 'contains');
    await vi.waitFor(() => expect(host.textContent).toContain(t('recordingReadFailed')));
    expect(api.managementRecordings).toHaveBeenCalledTimes(2);
    await click(button(host, 'Refresh recordings'));
    await vi.waitFor(() => expect(api.managementRecordings).toHaveBeenCalledTimes(3));
    expect(api.managementRecordings.mock.calls[2]?.[1]).toMatchObject({
        filter: { field: 'user', operator: 'contains', value: 'alice' },
    });
});

it('does not publish a late warmup failure from an earlier breadcrumb flow into the new route', async () => {
    const { api, access, page } = recordingCatalogFixture();
    type RecordingPage = Awaited<ReturnType<WebAccess['managementRecordings']>>;
    const first = Promise.withResolvers<RecordingPage>();
    const second = Promise.withResolvers<RecordingPage>();
    api.managementRecordings
        .mockReset()
        .mockImplementationOnce(() => first.promise)
        .mockImplementationOnce(() => second.promise);
    const { host, router } = await mount(
        '/Admin/admin/recordings/docker?auditlog=default',
        'recordings',
        access,
    );
    await vi.waitFor(() => expect(api.managementRecordings).toHaveBeenCalledOnce());
    await act(async () => router.navigate('/Admin/admin/recordings/other?auditlog=default'));
    await act(async () => first.reject(new RememberMeError('catalog-incomplete')));
    await vi.waitFor(() => expect(api.managementRecordings).toHaveBeenCalledTimes(2));
    expect(host.textContent).not.toContain('Catalog verification needs another read.');
    expect(host.querySelectorAll('[role="row"][data-id]')).toHaveLength(0);
    const other = {
        ...page.items[0],
        id: '70d5159d-a0e4-46ca-b011-c4f831f4ade0',
        flow: 'other',
    } as RecordingSummary;
    await act(async () => second.resolve({ items: [other], next: '', skipped: 0 }));
    await vi.waitFor(() => expect(button(host, `Open recording ${other.id}`).disabled).toBe(false));
    expect(host.textContent).not.toContain('Catalog verification needs another read.');
    expect(api.managementRecordings.mock.calls[1]?.[1]).toMatchObject({ flow: 'other' });
    expect(host.querySelectorAll('[role="row"][data-id]')).toHaveLength(1);
});

it('retains a cancelled read notice for its owned page without an automatic retry when returning from another main page', async () => {
    const { api, access, page } = recordingCatalogFixture();
    type RecordingPage = Awaited<ReturnType<WebAccess['managementRecordings']>>;
    const pending = Promise.withResolvers<RecordingPage>();
    api.managementRecordings
        .mockReset()
        .mockImplementationOnce(() => pending.promise)
        .mockResolvedValue(page);
    const { host, router } = await mount(
        '/Admin/admin/recordings/docker?auditlog=default',
        'workspace',
        access,
    );
    await vi.waitFor(() => expect(api.managementRecordings).toHaveBeenCalledOnce());
    await act(async () => router.navigate('/Admin/admin'));
    await act(async () => pending.reject(new RememberMeError('catalog-incomplete')));
    await vi.waitFor(() => expect(api.managementFlows).toHaveBeenCalledOnce());
    await act(async () => router.navigate('/Admin/admin/auditlogs/default/recordings?flow=docker'));
    await vi.waitFor(() =>
        expect(router.state.location.pathname).toBe('/Admin/admin/auditlogs/default/recordings'),
    );
    await vi.waitFor(() => expect(host.textContent).toContain(t('artifactCatalogCancelled')));
    expect(api.managementRecordings).toHaveBeenCalledOnce();
    expect(host.querySelectorAll('[role="row"][data-id]')).toHaveLength(0);
    await click(button(host, 'Refresh recordings'));
    await vi.waitFor(() => expect(api.managementRecordings).toHaveBeenCalledTimes(2));
    await vi.waitFor(() => expect(button(host, `Open recording ${id}`).disabled).toBe(false));
});

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
    expect(host.querySelector('.session-details button[aria-label="Close"]')).toBeNull();
    await click(button(host, t('workspaceSessions')));
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
            Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(
                input,
                value,
            );
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
        metadata: {
            Version: 1,
            ID: id,
            ProducerID: 'a'.repeat(64),
            Size: 7,
            SHA256: 'b'.repeat(64),
        },
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
    expect(verifyArtifact).not.toHaveBeenCalled();
    await verifyRecording(host);
    await vi.waitFor(() =>
        expect(host.querySelector('[aria-label="Routed player"]')).not.toBeNull(),
    );
    expect(api.downloadArtifact).toHaveBeenCalledExactlyOnceWith(
        image.request,
        expect.any(AbortSignal),
        expect.any(Function),
    );
    expect(api.managementAuditlogs).not.toHaveBeenCalled();
    expect(api.managementRecordings).not.toHaveBeenCalled();
    await act(async () =>
        router.navigate(`/Admin/admin/recordings/Other?recording=${id}&auditlog=default`),
    );
    await vi.waitFor(() => expect(host.querySelector('[aria-label="Routed player"]')).toBeNull());
    expect(verifyArtifact).toHaveBeenCalledOnce();
    // A repeated explicit check reruns the retained immutable bytes directly;
    // only the first check opens options. The changed selector must still fail.
    await click(button(host, t('verifyOpen')));
    await vi.waitFor(() =>
        expect(host.querySelector('[data-verification-result="failure"]')).not.toBeNull(),
    );
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
    await act(async () =>
        router.navigate(`/Admin/admin/recordings/Docker/${next}?auditlog=default`),
    );
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
            expect.any(Function),
        ),
    );
    expect(api.downloadArtifact).not.toHaveBeenCalled();
});
it('does not automatically retry a denied sole-source Recording read after source discovery', async () => {
    const { access, api } = fixture();
    api.managementRecordings.mockRejectedValue(new Error('controlled recording read denial'));
    const { host } = await mount('/Admin/admin/auditlogs/default/recordings', 'recordings', access);
    await vi.waitFor(() => expect(host.textContent).toContain(t('recordingReadFailed')));
    expect(api.managementRecordings).toHaveBeenCalledOnce();
});
it('shows live verification progress in one request and adopts only its completed page without a continuation click', async () => {
    const { access, api, page } = recordingCatalogFixture();
    const pending = Promise.withResolvers<Awaited<ReturnType<WebAccess['managementRecordings']>>>();
    api.managementRecordings.mockReset().mockImplementationOnce(() => pending.promise);
    const { host } = await mount('/Admin/admin/auditlogs/default/recordings', 'recordings', access);
    await vi.waitFor(() => expect(api.managementRecordings).toHaveBeenCalledOnce());
    const report = api.managementRecordings.mock.calls[0]?.[3];
    expect(report).toBeTypeOf('function');
    await act(async () => report?.({ phase: 'verifying', completed: 230, total: 284 }));
    expect(host.textContent).toContain(t('scanVerifying'));
    expect(host.textContent).toContain('230 / 284');
    expect(host.querySelector('button[aria-label="Refresh recordings"]')).toBeNull();
    expect(button(host, t('artifactCatalogCancel')).disabled).toBe(false);
    expect(api.managementRecordings).toHaveBeenCalledOnce();
    expect(host.querySelectorAll('[role="row"][data-id]').length).toBe(0);
    expect(host.textContent).not.toContain('Catalog verification needs another read.');
    expect(host.textContent).not.toContain('Continue verification');
    await act(async () => pending.resolve(page));
    await vi.waitFor(() => expect(button(host, `Open recording ${id}`).disabled).toBe(false));
    expect(api.managementRecordings).toHaveBeenCalledOnce();
    expect(host.textContent).not.toContain(t('scanVerifying'));
    expect(api.downloadArtifact).not.toHaveBeenCalled();
});
it('reopens the same encrypted Recording through the router with a fresh owned transfer and a visible local-key form', async () => {
    const { access, api } = fixture();
    vi.mocked(openRecording).mockImplementation(async (image) =>
        openedFixture(image.request.kind === 'recording' ? image.request.id : '', 'a'.repeat(64), {
            encrypted: true,
            requiresKey: true,
            recipient: `SHA256:${'A'.repeat(43)}`,
            decryption: 'not-checked',
            flow: '',
            sessionId: '',
        }),
    );
    const image: ReceivedArtifact = {
        request: { kind: 'recording', auditlog: 'default', id },
        transport: 'complete',
        evidence: 'unverified',
        metadata: {
            Version: 1,
            ID: id,
            ProducerID: 'a'.repeat(64),
            Size: 7,
            SHA256: 'b'.repeat(64),
        },
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
    expect(inspectProtection).not.toHaveBeenCalled();
    await vi.waitFor(() => expect(button(host, t('verifyOpen')).disabled).toBe(false));
    await click(button(host, t('verifyOpen')));
    await vi.waitFor(() =>
        expect(
            document.querySelector('[aria-modal="true"] .artifact-key input[type="file"]'),
        ).not.toBeNull(),
    );
    expect(host.querySelector(`[aria-label="${t('artifactBackToList')}"]`)).toBeNull();
    const openDialog = [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].find((node) =>
        node.checkVisibility({ visibilityProperty: true }),
    );
    if (!openDialog) {
        throw new Error('Missing visible verification options');
    }
    await click(button(openDialog, t('cancel')));
    await click(button(host, t('workspaceRecordings')));
    await vi.waitFor(() =>
        expect(router.state.location.pathname).toBe('/Admin/admin/auditlogs/default/recordings'),
    );
    expect(router.state.location.search).toBe('');
    await vi.waitFor(() =>
        expect(
            [...document.querySelectorAll('[role="dialog"]')].some((node) =>
                node.checkVisibility({ visibilityProperty: true }),
            ),
        ).toBe(false),
    );
    await act(async () => router.navigate(path));
    await vi.waitFor(() => expect(api.downloadArtifact).toHaveBeenCalledTimes(2));
    await vi.waitFor(() => expect(button(host, t('verifyOpen')).disabled).toBe(false));
    await click(button(host, t('verifyOpen')));
    await vi.waitFor(() =>
        expect(
            document.querySelector('[aria-modal="true"] .artifact-key input[type="file"]'),
        ).not.toBeNull(),
    );
    expect(verifyArtifact).not.toHaveBeenCalled();
});
it('resolves an event outside the first page without inventing a flow filter or a duplicate breadcrumb level', async () => {
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
        expect(router.state.location.pathname).toBe(`/Admin/admin/auditlogs/default/events/${id}`),
    );
    expect(router.state.location.search).toBe('');
    await vi.waitFor(() =>
        expect(host.querySelector('.audit-event-details')?.textContent).toContain(
            'session.event.35',
        ),
    );
    expect(host.querySelector('[role="dialog"]')).toBeNull();
    await act(async () => router.navigate(`/Admin/admin/auditlogs/default/Other?event=${id}`));
    await vi.waitFor(() => expect(host.textContent).toContain(t('managementPageNotFound')));
    expect(host.querySelector('[role="alert"]')).toBeNull();
    expect(host.querySelector('.audit-event-details')).toBeNull();
    expect(router.state.location.pathname).toBe('/Admin/admin/auditlogs/default/Other');
    expect(router.state.location.search).toBe(`?event=${id}`);
});
