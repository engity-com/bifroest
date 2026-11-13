import { act, createElement, type ReactNode, useMemo } from 'react';
import { createRoot } from 'react-dom/client';
import { createMemoryRouter, useLocation, useNavigate } from 'react-router';
import { RouterProvider } from 'react-router/dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { managementPath, parseManagementLocation } from '../src/application/management-location';
import type { EvidenceMetadata } from '../src/artifacts/evidence-protocol';
import { openRecording } from '../src/artifacts/open-recording';
import { inspectProtection } from '../src/artifacts/protection';
import type { ReceivedArtifact } from '../src/artifacts/protocol';
import { verifyArtifact } from '../src/artifacts/verify';
import type { RecordingSummary, SessionItem } from '../src/management/protocol';
import type { WebAccess } from '../src/remember';
import { uuidText } from '../src/shared/uuid';
import { detailPreferenceKey } from '../src/ui/detail-preference';
import { ManagementWorkspace } from '../src/ui/ManagementWorkspace';
import { t } from '../src/ui/messages';
import { openedFixture } from './open-recording-fixture';
import { recordingRuntimeFixture } from './recording-runtime-fixture';
import '../src/ui/app.css';

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
        createElement('section', { 'aria-label': 'Relationship player' }, verificationControls),
}));
const scope = { origin: 'https://app.example.org', slug: 'Admin' };
const sessionID = '70d5159d-a0e4-46ca-b011-c4f831f4ade0';
const recordingID = '34e34ab8-7457-4d88-a5e4-c57791775c3a';
const eventID = '3db111da-c6f0-497a-a041-2eb4f8eb7c79';
const session: SessionItem = {
    id: sessionID,
    flow: 'worker',
    auditlog: 'default',
    state: 'authorized',
    user: 'original-login',
    remote: 'original-login@127.0.0.1',
    createdAt: '2026-01-01T00:00:00Z',
    owner: null,
};
const recording: RecordingSummary = {
    id: recordingID,
    auditlog: 'default',
    flow: 'worker',
    sessionId: sessionID,
    user: 'original-login',
    producerId: 'a'.repeat(64),
    format: 'bcast/v1',
    status: 'completed',
    startedAt: '2026-01-01T00:00:00Z',
    endedAt: '2026-01-01T00:00:01Z',
    containerBytes: 500,
    chunkCount: 1,
    encrypted: false,
    verificationScope: 'full',
};
const event = {
    name: 'session.recording.completed',
    outcome: 'success',
    flow: 'worker',
    sessionId: sessionID,
    recordingId: recordingID,
    reason: 'disconnected',
};
const noLock = () => {};
const cleanups: (() => void)[] = [];
beforeEach(() => {
    vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
    localStorage.setItem(detailPreferenceKey, 'full');
    vi.mocked(openRecording).mockImplementation(async (image) =>
        openedFixture(image.request.kind === 'recording' ? image.request.id : '', 'a'.repeat(64), {
            flow: 'worker',
            sessionId: sessionID,
        }),
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
    localStorage.removeItem(detailPreferenceKey);
});
function image(kind: 'audit' | 'recording'): ReceivedArtifact {
    return {
        request:
            kind === 'audit'
                ? { kind, auditlog: 'default' }
                : { kind, auditlog: 'default', id: recordingID },
        transport: 'complete',
        evidence: 'unverified',
        metadata:
            kind === 'audit'
                ? {
                      Version: 1,
                      Name: 'default',
                      Producer: 'a'.repeat(64),
                      Recipient: '',
                      Files: [],
                  }
                : {
                      Version: 1,
                      ID: recordingID,
                      ProducerID: 'a'.repeat(64),
                      Size: 7,
                      SHA256: 'b'.repeat(64),
                  },
        files: [
            { name: kind === 'audit' ? 'head.cbor' : 'recording', data: new Blob(['fixture']) },
        ],
    };
}
function evidence(kind: 'audit' | 'recording'): EvidenceMetadata {
    return {
        kind,
        validation: 'private',
        trust: 'untrusted',
        producer: 'a'.repeat(64),
        expectedRecipient: '',
        decryption: 'not-encrypted',
        recordingId: kind === 'recording' ? recordingID : '',
        auditScope: kind === 'audit' ? 'complete' : '',
        records: '1',
        privateRecords: '0',
        outputFormat: kind === 'audit' ? 'jsonl' : 'cast',
    };
}
function fixture() {
    const api = {
        snapshot: () => ({
            scope,
            flow: { name: 'admin', title: 'Admin' },
            principal: 'original-login',
            environment: 'management',
            expiresAt: '2100-01-01T00:00:00Z',
        }),
        status: () => 'active',
        managementStatus: () => 'active',
        subscribeStatus: () => () => {},
        openManagement: vi.fn(() => ({ disconnect: vi.fn() })),
        managementSessions: vi.fn<WebAccess['managementSessions']>(async () => ({
            items: [session],
            next: '',
            skipped: 0,
        })),
        managementSession: vi.fn<WebAccess['managementSession']>(async () => session),
        managementFlows: vi.fn<WebAccess['managementFlows']>(async () => ({
            items: [],
            next: '',
            skipped: 0,
        })),
        managementAuditlogs: vi.fn<WebAccess['managementAuditlogs']>(async () => ({
            items: [{ name: 'default', enabled: true, recordingEnabled: true, encrypted: false }],
            next: '',
            skipped: 0,
        })),
        managementRecordings: vi.fn<WebAccess['managementRecordings']>(async () => ({
            items: [recording],
            next: '',
            skipped: 0,
            total: 1,
        })),
        managementAuditEvents: vi.fn<WebAccess['managementAuditEvents']>(
            async (_source, options) => ({
                items: [
                    {
                        id: eventID,
                        key: `1:0:${eventID}`,
                        recordedAt: '2026-01-01T00:00:00Z',
                        event: options?.sensitive
                            ? event
                            : { name: event.name, outcome: event.outcome },
                    },
                ],
                next: '',
                skipped: 0,
                total: 1,
                source: {
                    auditlog: 'default',
                    encrypted: false,
                    sensitive: options?.sensitive ?? false,
                    verification: 'server-overview',
                },
            }),
        ),
        managementVerifyRecordings: vi.fn<WebAccess['managementVerifyRecordings']>(),
        downloadArtifact: vi.fn<WebAccess['downloadArtifact']>(async (request) =>
            image(request.kind),
        ),
    };
    vi.mocked(inspectProtection).mockImplementation(async (selected) => ({
        ...evidence(selected.request.kind),
        validation: 'outer',
        outputFormat: '',
    }));
    vi.mocked(verifyArtifact).mockImplementation(async (selected, options) => ({
        request: selected.request,
        provenance: 'bytes-only',
        metadata: evidence(selected.request.kind),
        output:
            selected.request.kind === 'recording'
                ? new Blob([
                      `{}\n# bifroest:metadata:v1 ${JSON.stringify({ recordingId: recordingID, flow: 'worker', sessionId: sessionID })}\n`,
                  ])
                : new Blob([
                      `${JSON.stringify({ id: eventID, recordedAt: '2026-01-01T00:00:00Z', event: options.sensitive ? event : { name: event.name, outcome: event.outcome } })}\n`,
                  ]),
    }));
    return { api, access: api as unknown as WebAccess };
}
function Scene({ access }: { access: WebAccess }) {
    const location = useLocation();
    const navigate = useNavigate();
    const route = useMemo(() => parseManagementLocation(scope, location), [location]);
    const stopped = useMemo(() => new AbortController(), []);
    if (!route) {
        throw new Error('Invalid relation route');
    }
    return createElement(ManagementWorkspace, {
        access,
        owner: 1,
        active: true,
        disabled: false,
        onActionLock: noLock,
        onReauthenticate: noLock,
        signal: stopped.signal,
        location: route,
        onNavigate: (_owner, target, replace) => {
            void navigate(managementPath(scope, target), { replace: replace ?? false });
        },
    });
}
async function mount(path: string, access: WebAccess) {
    const host = document.createElement('div');
    host.style.width = '1500px';
    document.body.append(host);
    const root = createRoot(host);
    const router = createMemoryRouter([{ path: '*', element: createElement(Scene, { access }) }], {
        initialEntries: [path],
    });
    cleanups.push(() => {
        root.unmount();
        router.dispose();
        host.remove();
    });
    await act(async () => root.render(createElement(RouterProvider, { router })));
    return { host, router };
}
function action(host: ParentNode, label: string) {
    const result = [...host.querySelectorAll<HTMLElement>('button,a')].find(
        (node) =>
            !node.closest('[hidden]') &&
            (node.getAttribute('aria-label') === label || node.textContent === label),
    );
    if (!result) {
        throw new Error(
            `Missing ${label}: ${JSON.stringify({ anchors: [...host.querySelectorAll('a')].map((node) => [node.getAttribute('aria-label'), node.getAttribute('href')]), columns: [...host.querySelectorAll('[role="columnheader"]')].map((node) => node.getAttribute('data-field')) })}`,
        );
    }
    return result;
}
const click = async (node: HTMLElement) => act(async () => node.click());
async function options(host: HTMLElement) {
    await click(action(host, t('verifyOpen')));
    const dialog = [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].find(
        (node) =>
            !node.closest('[aria-hidden="true"]') &&
            node.checkVisibility({ visibilityProperty: true }),
    );
    if (!dialog) {
        throw new Error('Missing verification options');
    }
    expect(dialog.textContent).toContain('default');
    return dialog;
}

it('puts Session ID first and uses exact reloadable flow/session targets from both session action surfaces', async () => {
    const { api, access } = fixture();
    const { host, router } = await mount('/Admin/admin/sessions/worker', access);
    await vi.waitFor(() =>
        expect(
            host
                .querySelector(
                    `[role="grid"][aria-label="${t('managementSessionsCaption')}"] [role="columnheader"]`,
                )
                ?.getAttribute('data-field'),
        ).toBe('id'),
    );
    const scroller = host.querySelector<HTMLElement>(
        `[role="grid"][aria-label="${t('managementSessionsCaption')}"] .MuiDataGrid-virtualScroller`,
    );
    if (!scroller) {
        throw new Error('Missing session dataset scroller');
    }
    await act(async () => {
        scroller.scrollLeft = scroller.scrollWidth;
        scroller.dispatchEvent(new Event('scroll'));
    });
    await vi.waitFor(() =>
        expect(
            host.querySelector(`a[aria-label="${t('showRecordings')} ${sessionID}"]`),
        ).not.toBeNull(),
    );
    const recordings = action(host, `${t('showRecordings')} ${sessionID}`);
    expect(recordings.querySelector('[data-testid="ScreenshotMonitorIcon"]')).not.toBeNull();
    await click(recordings);
    await vi.waitFor(() =>
        expect(router.state.location.pathname).toBe('/Admin/admin/auditlogs/default/recordings'),
    );
    expect(router.state.location.search).toBe(`?flow=worker&sessionId=${sessionID}`);
    await vi.waitFor(() => expect(api.managementRecordings).toHaveBeenCalledOnce());
    expect(api.managementRecordings.mock.calls[0]?.[1]).toMatchObject({
        flow: 'worker',
        sessionId: sessionID,
        filter: { field: 'sessionId', operator: 'equals', value: sessionID },
    });
    expect(api.downloadArtifact).not.toHaveBeenCalled();
    expect(api.managementVerifyRecordings).not.toHaveBeenCalled();
    await act(async () => router.navigate('/Admin/admin/sessions/worker'));
    await click(action(host, `${t('managementDetails')} ${sessionID}`));
    await vi.waitFor(() => expect(host.querySelector('.session-details')).not.toBeNull());
    const details = host.querySelector<HTMLElement>('.session-details');
    if (!details) {
        throw new Error('Missing session details');
    }
    expect(details.querySelector('button[aria-label="Close"]')).toBeNull();
    expect(action(details, t('showRecordings')).tagName).toBe('A');
    expect(
        action(details, t('showAuditlogs')).querySelector('[data-testid="FactCheckIcon"]'),
    ).not.toBeNull();
    await click(action(details, t('showAuditlogs')));
    await vi.waitFor(() => expect(api.managementAuditEvents).toHaveBeenCalledOnce());
    expect(router.state.location.pathname).toBe('/Admin/admin/auditlogs/default/events');
    expect(router.state.location.search).toBe(`?flow=worker&sessionId=${sessionID}`);
    expect(api.managementAuditEvents.mock.calls[0]?.[1]).toMatchObject({
        flow: 'worker',
        sessionId: sessionID,
        sensitive: false,
    });
});

it('links a recording to its own session in both the dataset and Details without opening the recording on an action click', async () => {
    const { api, access } = fixture();
    const { host, router } = await mount('/Admin/admin/recordings/worker?auditlog=default', access);
    await vi.waitFor(() => expect(api.managementRecordings).toHaveBeenCalledOnce());
    await click(action(host, `${t('showSession')} ${sessionID}`));
    await vi.waitFor(() => expect(api.managementSession).toHaveBeenCalledOnce());
    expect(api.managementSession.mock.calls[0]?.slice(0, 2)).toEqual(['worker', sessionID]);
    expect(api.downloadArtifact).not.toHaveBeenCalled();
    await act(async () => router.navigate('/Admin/admin/recordings/worker?auditlog=default'));
    await click(action(host, `${t('recordingOpen')} ${recordingID}`));
    expect(inspectProtection).not.toHaveBeenCalled();
    expect(verifyArtifact).not.toHaveBeenCalled();
    const verificationDialog = await options(host);
    await click(action(verificationDialog, t('verifyStart')));
    await vi.waitFor(() =>
        expect(host.querySelector('[aria-label="Relationship player"]')).not.toBeNull(),
    );
    const details = host.querySelector<HTMLElement>('.recording-evidence');
    if (!details) {
        throw new Error('Missing recording Details');
    }
    expect(details.textContent).toContain(t('detailsTitle'));
    const sessionLink = details.querySelector<HTMLAnchorElement>(
        `a[href="/#Admin/-/sessions/worker/${uuidText(sessionID)}"]`,
    );
    expect(sessionLink?.textContent).toBe(sessionID);
    expect(
        action(details, t('showSession')).querySelector(
            '[data-testid="PeopleOutlineOutlinedIcon"]',
        ),
    ).not.toBeNull();
    expect(host.querySelector('.section-heading button[aria-label="Back to list"]')).toBeNull();
    expect(api.downloadArtifact).toHaveBeenCalledOnce();
});

it('retires verified recording output on a changed session selector without automatically verifying again', async () => {
    const { api, access } = fixture();
    const { host, router } = await mount(
        `/Admin/admin/recordings/worker/${recordingID}?auditlog=default`,
        access,
    );
    const dialog = await options(host);
    await click(action(dialog, t('verifyStart')));
    await vi.waitFor(() =>
        expect(host.querySelector('[aria-label="Relationship player"]')).not.toBeNull(),
    );
    const other = '70d5159d-a0e4-46ca-b011-c4f831f4ade1';
    await act(async () =>
        router.navigate(
            `/Admin/admin/recordings/worker/${recordingID}?auditlog=default&sessionId=${other}`,
        ),
    );
    await vi.waitFor(() =>
        expect(host.querySelector('[aria-label="Relationship player"]')).toBeNull(),
    );
    expect(verifyArtifact).toHaveBeenCalledOnce();
    expect(api.downloadArtifact).toHaveBeenCalledOnce();
    await click(action(host, t('verifyOpen')));
    await vi.waitFor(() =>
        expect(host.querySelector('[data-verification-result="failure"]')).not.toBeNull(),
    );
    expect(verifyArtifact).toHaveBeenCalledTimes(2);
    expect(host.querySelector('[aria-label="Relationship player"]')).toBeNull();
});

it('uses the same event Details and breadcrumb for server and local data, with explicit eye consent and source-switch toolbar action', async () => {
    const { api, access } = fixture();
    const { host, router } = await mount('/Admin/admin/auditlogs/default', access);
    await vi.waitFor(() => expect(api.managementAuditEvents).toHaveBeenCalledOnce());
    expect(api.managementAuditEvents.mock.calls[0]?.[1]?.sensitive).toBe(false);
    expect(host.querySelector(`a[aria-label="${t('showSession')} ${sessionID}"]`)).toBeNull();
    await click(action(host, t('adminGridShowDetails')));
    await vi.waitFor(() => expect(api.managementAuditEvents).toHaveBeenCalledTimes(2));
    expect(api.managementAuditEvents.mock.calls[1]?.[1]?.sensitive).toBe(true);
    expect(
        action(host, `${t('showRecording')} ${recordingID}`).querySelector(
            '[data-testid="ScreenshotMonitorIcon"]',
        ),
    ).not.toBeNull();
    await click(action(host, `${t('auditEventDetails')} ${eventID}`));
    await vi.waitFor(() => expect(host.querySelector('.audit-event-details')).not.toBeNull());
    expect(router.state.location.pathname).toBe(`/Admin/admin/auditlogs/default/events/${eventID}`);
    expect(router.state.location.search).toBe('');
    expect(host.querySelector('.admin-breadcrumbs [aria-current="page"]')?.textContent).toBe(
        uuidText(eventID),
    );
    const serverDetails = host.querySelector<HTMLElement>('.audit-event-details');
    if (!serverDetails) {
        throw new Error('Missing event details');
    }
    expect(serverDetails.textContent).toContain(t('serverReported'));
    expect(serverDetails.textContent).toContain(t('detailsTitle'));
    expect(action(serverDetails, t('showSession')).getAttribute('href')).toBe(
        `/#Admin/-/sessions/worker/${uuidText(sessionID)}`,
    );
    expect(action(serverDetails, t('showRecording')).getAttribute('href')).toBe(
        `/#Admin/-/auditlogs/default/recordings?recording=${uuidText(recordingID)}`,
    );
    expect(serverDetails.querySelector('button[aria-label="Close"]')).toBeNull();
    await click(action(host, 'default'));
    const dialog = await options(host);
    expect(api.downloadArtifact).not.toHaveBeenCalled();
    expect(
        dialog.querySelector('input[type="checkbox"]')?.closest('label')?.textContent,
    ).not.toContain('sensitive');
    expect(
        dialog.querySelector('[data-testid="VisibilityIcon"], [data-testid="VisibilityOffIcon"]'),
    ).toBeNull();
    await click(action(dialog, t('verifyStart')));
    await vi.waitFor(() =>
        expect(
            host.querySelector(`[aria-label="${t('auditLocalRegion')}"] [role="row"][data-id]`),
        ).not.toBeNull(),
    );
    expect(api.downloadArtifact).toHaveBeenCalledOnce();
    expect(vi.mocked(verifyArtifact).mock.calls[0]?.[1].sensitive).toBe(true);
    expect(
        action(host, t('directServerData')).querySelector('[data-testid="DirectServerIcon"]'),
    ).not.toBeNull();
    const local = host.querySelector<HTMLElement>(`[aria-label="${t('auditLocalRegion')}"]`);
    if (!local) {
        throw new Error('Missing local grid');
    }
    await click(action(local, `${t('auditEventDetails')} 0:${eventID}`));
    await vi.waitFor(() =>
        expect(router.state.location.pathname).toBe(
            `/Admin/admin/auditlogs/default/events/${eventID}`,
        ),
    );
    await vi.waitFor(() => expect(local.querySelector('.audit-event-details')).not.toBeNull());
    const localDetails = local.querySelector<HTMLElement>('.audit-event-details');
    if (!localDetails) {
        throw new Error('Missing local event details');
    }
    expect(localDetails.className).toBe(serverDetails.className);
    expect(localDetails.textContent).toContain(t('detailsTitle'));
    expect(action(localDetails, t('showSession')).getAttribute('href')).toBe(
        action(serverDetails, t('showSession')).getAttribute('href'),
    );
    expect(action(localDetails, t('showRecording')).getAttribute('href')).toBe(
        `/#Admin/-/auditlogs/default/recordings?recording=${uuidText(recordingID)}`,
    );
    expect(localDetails.querySelector('button[aria-label="Close"]')).toBeNull();
    await click(action(host, 'default'));
    const serverReads = api.managementAuditEvents.mock.calls.length;
    await vi.waitFor(() =>
        expect((action(local, t('adminGridHideDetails')) as HTMLButtonElement).disabled).toBe(
            false,
        ),
    );
    await click(action(local, t('adminGridHideDetails')));
    await vi.waitFor(() => expect(verifyArtifact).toHaveBeenCalledTimes(2));
    await vi.waitFor(() => expect(action(local, t('directServerData'))).toBeDefined());
    expect(api.managementAuditEvents).toHaveBeenCalledTimes(serverReads);
    expect(api.downloadArtifact).toHaveBeenCalledOnce();
    expect(vi.mocked(verifyArtifact).mock.calls[1]?.[1].sensitive).toBe(false);
    await vi.waitFor(() =>
        expect(
            local.querySelector(`button[aria-label="${t('auditEventDetails')} 0:${eventID}"]`),
        ).not.toBeNull(),
    );
    await click(action(local, `${t('auditEventDetails')} 0:${eventID}`));
    await vi.waitFor(() =>
        expect(router.state.location.pathname).toBe(
            `/Admin/admin/auditlogs/default/events/${eventID}`,
        ),
    );
    expect(router.state.location.search).toBe('');
    await click(action(host, 'default'));
    await click(action(host, t('directServerData')));
    expect(host.querySelector('[data-verification-result]')?.getClientRects().length ?? 0).toBe(0);
    expect(api.downloadArtifact).toHaveBeenCalledOnce();
    expect(verifyArtifact).toHaveBeenCalledTimes(2);
});

it('does not invent a session target from a route filter when an event withholds its own flow', async () => {
    const { api, access } = fixture();
    api.managementAuditEvents.mockImplementation(async (_source, options) => ({
        items: [
            {
                id: eventID,
                key: `1:0:${eventID}`,
                recordedAt: '2026-01-01T00:00:00Z',
                event: options?.sensitive
                    ? { name: event.name, sessionId: sessionID, recordingId: recordingID }
                    : { name: event.name },
            },
        ],
        next: '',
        skipped: 0,
        source: {
            auditlog: 'default',
            encrypted: false,
            sensitive: options?.sensitive ?? false,
            verification: 'server-overview',
        },
    }));
    const { host } = await mount('/Admin/admin/auditlogs/default/worker', access);
    await vi.waitFor(() => expect(api.managementAuditEvents).toHaveBeenCalledOnce());
    await click(action(host, t('adminGridShowDetails')));
    await vi.waitFor(() => expect(api.managementAuditEvents).toHaveBeenCalledTimes(2));
    await click(action(host, `${t('auditEventDetails')} ${eventID}`));
    await vi.waitFor(() => expect(host.querySelector('.audit-event-details')).not.toBeNull());
    const details = host.querySelector('.audit-event-details');
    expect(details?.textContent).toContain(sessionID);
    expect(details?.querySelector('a[href*="/sessions/"]')).toBeNull();
    expect(details?.querySelector('a[href*="recording="]')).not.toBeNull();
});
