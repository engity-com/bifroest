import { act, createElement, type ReactNode, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { page as browserPage, userEvent } from 'vitest/browser';
import { ArtifactCatalog } from '../src/artifacts/ArtifactCatalog';
import { ArtifactPanel } from '../src/artifacts/ArtifactPanel';
import { EvidenceError } from '../src/artifacts/evidence-protocol';
import type { ArtifactRequest, ReceivedArtifact } from '../src/artifacts/protocol';
import { RecordingIndexBuilder } from '../src/artifacts/recording-index';
import { type RecordingVerificationBatch, verifyArtifact } from '../src/artifacts/verify';
import type { AuditOverviewPage } from '../src/management/audit-overview';
import type { RecordingSummary } from '../src/management/protocol';
import type { RecordingSourceImages } from '../src/management/source-transfer';
import { WebAccess } from '../src/remember/client';
import { Http } from '../src/remember/http';
import { RememberMeError } from '../src/remember/protocol';
import { uuidText } from '../src/shared/uuid';
import { detailPreferenceKey, setDetailedView } from '../src/ui/detail-preference';
import { ManagementNavigationContext } from '../src/ui/management-navigation';
import { t } from '../src/ui/messages';
import { profileResetEvent } from '../src/ui/profile-reset';
import '../src/ui/app.css';

vi.mock('../src/artifacts/verify', async (original) => {
    const check = vi.fn<typeof verifyArtifact>();
    return {
        ...(await original<typeof import('../src/artifacts/verify')>()),
        verifyArtifact: check,
        createRecordingVerificationBatch: vi.fn(
            async (_source: string, signal: AbortSignal): Promise<RecordingVerificationBatch> => ({
                receive: async (request) => recordingImage(request),
                verify: (image, options, key, progress) =>
                    check(image, options, key, signal, progress),
                dispose: vi.fn(),
            }),
        ),
    };
});

const id = '34e34ab8-7457-4d88-a5e4-c57791775c3a';
const source = {
    name: 'default',
    enabled: true,
    recordingEnabled: true,
    encrypted: false,
    producerId: 'a'.repeat(64),
};
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
        producerId: source.producerId,
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
function recordingImage(request: ArtifactRequest): ReceivedArtifact {
    if (request.kind !== 'recording') {
        throw new RememberMeError('denied');
    }
    return {
        request,
        transport: 'complete',
        evidence: 'unverified',
        metadata: {
            Version: 1,
            ID: request.id,
            ProducerID: source.producerId,
            Size: 7,
            SHA256: 'b'.repeat(64),
        },
        files: [{ name: 'recording', data: new Blob(['fixture']) }],
    };
}
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
    vi.spyOn(WebAccess.prototype, 'downloadArtifact').mockImplementation(async (request) =>
        recordingImage(request),
    );
    vi.spyOn(WebAccess.prototype, 'openRecordingSource').mockImplementation(
        async (auditlog): Promise<RecordingSourceImages> => {
            const values = (async function* () {
                yield {
                    request: { kind: 'recording' as const, auditlog, id },
                    image: {
                        bytes: new ArrayBuffer(3),
                        status: 200,
                        mediaType: 'application/vnd.bifroest.management-transfer.v1',
                    },
                    index: 1,
                    total: 1,
                    encrypted: false,
                    recipient: '',
                };
            })();
            return Object.assign(values, { closed: Promise.resolve(), cancel: vi.fn() });
        },
    );
    vi.mocked(verifyArtifact).mockImplementation(async (image, options) => ({
        request: image.request,
        provenance: 'bytes-only',
        output: null,
        metadata: {
            kind: image.request.kind,
            validation: options.level,
            trust: options.producer ? 'pinned' : 'untrusted',
            producer: options.producer || source.producerId,
            expectedRecipient: options.recipient,
            decryption: 'not-encrypted',
            recordingId: image.request.kind === 'recording' ? image.request.id : '',
            ...(options.metadata
                ? {
                      recordingContext: {
                          flow: 'docker',
                          sessionId: id,
                          user: 'locally-verified-user',
                          startedAt: '2026-11-05T00:00:00Z',
                          endedAt: '2026-11-05T00:00:01Z',
                          status: 'completed' as const,
                          chunkCount: 1,
                      },
                  }
                : {}),
            auditScope: options.auditScope,
            records: '0',
            privateRecords: '0',
            outputFormat: '',
        },
    }));
    vi.spyOn(WebAccess.prototype, 'managementVerifyRecordings');
});
afterEach(async () => {
    await act(async () => {
        for (const cleanup of cleanups.splice(0)) {
            cleanup();
        }
    });
    vi.restoreAllMocks();
    vi.clearAllMocks();
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
    const result = [...host.querySelectorAll<HTMLButtonElement>('button,a[href]')].find(
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
    expect(dialog.querySelector<HTMLInputElement>('input[maxlength="64"]')?.value).toBe(
        source.producerId,
    );
    expect(dialog.querySelector<HTMLInputElement>('input[type="checkbox"]')?.checked).toBe(true);
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
    await vi.waitFor(() =>
        expect(host.querySelector('[aria-current="page"]')?.textContent).toBe(uuidText(id)),
    );
    expect(host.querySelector(`[aria-label="${t('auditEventDetails')}"]`)?.textContent).toContain(
        t('detailsTitle'),
    );
    expect(host.querySelector(`[aria-label="${t('auditOverviewBack')}"]`)).toBeNull();
    expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledOnce();
    expect(host.querySelector('.audit-event-details')?.textContent).toContain(event.event.name);
    expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
    await click(button(host, 'default'));
    await vi.waitFor(() => expect(eventRows(host)).toHaveLength(1));
    expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledOnce();
});

it('keeps encrypted audit rows when the eye requests local decryption, without a server reread or an automatic transfer', async () => {
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
    await vi.waitFor(() => expect(eventRows(host)).toHaveLength(1));
    const eye = host
        .querySelector<HTMLButtonElement>('[data-testid="VisibilityIcon"]')
        ?.closest('button');
    if (!eye) {
        throw new Error('Missing private-details eye');
    }
    await click(eye);
    expect(eventRows(host)).toHaveLength(1);
    expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledOnce();
    expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
    expect(verifyArtifact).not.toHaveBeenCalled();
    const dialog = [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].find((node) =>
        node.checkVisibility({ visibilityProperty: true }),
    );
    expect(dialog?.textContent).toContain(t('artifactKeyFile'));
    expect(host.textContent).toContain(t('auditPrivateEncrypted'));
    if (!dialog) {
        throw new Error('Missing explicit local-decryption options');
    }
    await click(button(dialog, t('cancel')));
    await click(button(host, t('adminGridHideDetails')));
    expect(eventRows(host)).toHaveLength(1);
    expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledOnce();
    expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
});

it('returns from the audit-source catalog to the retained page without spending another heavy read', async () => {
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
    const grid = host.querySelector('[role="grid"][aria-label="Audit events"]');
    await click(button(host, t('workspaceAuditlogs')));
    await click(button(host, 'Open audit log default'));
    await vi.waitFor(() =>
        expect(
            host.querySelector('[role="grid"][aria-label="Audit events"] [data-id]'),
        ).not.toBeNull(),
    );
    expect(host.querySelector('[role="grid"][aria-label="Audit events"]')).toBe(grid);
    expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledOnce();
    expect(WebAccess.prototype.managementAuditlogs).toHaveBeenCalledOnce();
});

it('preserves the completed encrypted audit page and its cursor when decryption is cancelled', async () => {
    vi.mocked(WebAccess.prototype.managementAuditEvents)
        .mockResolvedValueOnce({
            ...overview,
            next: 'bae1.next',
            total: 21,
            source: { ...overview.source, encrypted: true },
        })
        .mockResolvedValue({
            ...overview,
            total: 21,
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
    await vi.waitFor(() => expect(eventRows(host)).toHaveLength(1));
    await click(button(host, 'Go to next page'));
    await vi.waitFor(() =>
        expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledTimes(2),
    );
    const footer = () =>
        host.querySelector(
            `[aria-label="${t('auditOverview')}"] .MuiTablePagination-displayedRows`,
        );
    await vi.waitFor(() => expect(footer()?.textContent).toContain('21–21'));
    await click(button(host, t('auditDecryptDetails')));
    const dialog = [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].find((node) =>
        node.checkVisibility({ visibilityProperty: true }),
    );
    if (!dialog) {
        throw new Error('Missing decryption options');
    }
    await click(button(dialog, t('cancel')));
    expect(eventRows(host)).toHaveLength(1);
    expect(footer()?.textContent).toContain('21–21');
    expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledTimes(2);
    expect(vi.mocked(WebAccess.prototype.managementAuditEvents).mock.calls[1]?.[1]?.after).toBe(
        'bae1.next',
    );
    expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
});

it('reports a real 429 distinctly and waits for an explicit refresh instead of retrying during navigation', async () => {
    vi.mocked(WebAccess.prototype.managementAuditEvents)
        .mockRejectedValueOnce(new RememberMeError('rate-limited'))
        .mockResolvedValue(overview);
    const host = await mount(
        createElement(ArtifactPanel, {
            access: access(),
            view: 'auditlogs',
            active: true,
            disabled: false,
        }),
    );
    await click(button(host, 'Open audit log default'));
    await vi.waitFor(() => expect(host.textContent).toContain('Request limit reached'));
    await click(button(host, t('workspaceAuditlogs')));
    await click(button(host, 'Open audit log default'));
    expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledOnce();
    await click(button(host, t('auditRefreshEvents')));
    await vi.waitFor(() => expect(eventRows(host)).toHaveLength(1));
    expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledTimes(2);
});

it('offers local decryption for an empty encrypted flow scope instead of treating hidden private fields as absent', async () => {
    vi.mocked(WebAccess.prototype.managementAuditEvents).mockResolvedValue({
        ...overview,
        items: [],
        total: 0,
        source: { ...overview.source, encrypted: true },
    });
    const navigate = vi.fn();
    const host = await mount(
        createElement(
            ManagementNavigationContext.Provider,
            {
                value: {
                    location: {
                        managementFlow: 'management',
                        page: 'auditlogs',
                        auditlog: 'default',
                        flow: 'docker-encrypted',
                    },
                    navigate,
                },
            },
            createElement(ArtifactPanel, {
                access: access(),
                view: 'auditlogs',
                active: true,
                disabled: false,
            }),
        ),
    );
    await vi.waitFor(() => expect(host.textContent).toContain(t('auditEncryptedFilter')));
    expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledOnce();
    const unlock = host.querySelector<HTMLButtonElement>('.MuiDataGrid-overlay button');
    if (!unlock) {
        throw new Error('Missing empty-state decryption action');
    }
    await act(async () => userEvent.click(unlock));
    const dialog = [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].find((node) =>
        node.checkVisibility({ visibilityProperty: true }),
    );
    expect(dialog?.textContent).toContain(t('artifactKeyFile'));
    expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
    expect(verifyArtifact).not.toHaveBeenCalled();
    expect(navigate).not.toHaveBeenCalled();
    expect(vi.mocked(WebAccess.prototype.managementAuditEvents).mock.calls[0]?.[1]?.flow).toBe(
        'docker-encrypted',
    );
});

it('changes artifact presentation locally without clearing filters, paging, or spending another read', async () => {
    const previous = localStorage.getItem(detailPreferenceKey);
    const host = await mount(
        createElement(ArtifactCatalog, {
            access: access(),
            active: true,
            disabled: false,
            onSelect: vi.fn(),
        }),
    );
    await vi.waitFor(() => expect(button(host, `Open recording ${id}`).disabled).toBe(false));
    const before = vi.mocked(WebAccess.prototype.managementRecordings).mock.calls.length;
    const eye = host
        .querySelector('[data-testid="VisibilityOffIcon"],[data-testid="VisibilityIcon"]')
        ?.closest('button');
    if (!eye) {
        throw new Error('Missing detail eye');
    }
    await click(eye);
    expect(WebAccess.prototype.managementRecordings).toHaveBeenCalledTimes(before);
    expect(WebAccess.prototype.managementAuditlogs).toHaveBeenCalledOnce();
    expect(button(host, `Open recording ${id}`).disabled).toBe(false);
    await act(async () => setDetailedView(previous !== 'compact'));
    if (previous === null) {
        localStorage.removeItem(detailPreferenceKey);
    }
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
    const switchCollection = [
        ...host.querySelectorAll<HTMLAnchorElement>('a[aria-label="Recordings default"]'),
    ].find((node) => !node.closest('[hidden]'));
    expect(switchCollection?.getAttribute('aria-disabled')).toBe('true');
    if (!switchCollection) {
        throw new Error('Missing locked same-source toolbar action');
    }
    await click(switchCollection);
    expect(WebAccess.prototype.managementRecordings).not.toHaveBeenCalled();
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
    vi.mocked(WebAccess.prototype.managementRecordings).mockImplementation(
        async (_source, options) => ({
            items: [recording],
            next: options?.after ? '' : 'bmp1.next',
            skipped: 0,
            total: 21,
        }),
    );
    let signal: AbortSignal | undefined;
    vi.mocked(verifyArtifact).mockImplementation((_image, _options, _key, stopped) => {
        signal = stopped;
        return new Promise((_resolve, reject) => {
            stopped?.addEventListener('abort', () => reject(new RememberMeError('cancelled')), {
                once: true,
            });
        });
    });
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
    await vi.waitFor(() => expect(verifyArtifact).toHaveBeenCalledOnce());
    expect(WebAccess.prototype.managementVerifyRecordings).not.toHaveBeenCalled();
    expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
    expect(vi.mocked(WebAccess.prototype.openRecordingSource).mock.calls[0]?.[0]).toBe('default');
    expect(button(host, 'Go to next page').disabled).toBe(true);
    expect(host.querySelector<HTMLElement>('.MuiDataGrid-virtualScrollerRenderZone')?.inert).toBe(
        true,
    );
    expect(signal?.aborted).toBe(false);
    await click(button(host, t('verifyAllCancel')));
    await vi.waitFor(() => expect(signal?.aborted).toBe(true));
    await act(async () => userEvent.click(button(host, 'Go to next page')));
    await vi.waitFor(() =>
        expect(WebAccess.prototype.managementRecordings).toHaveBeenCalledTimes(2),
    );
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

it('publishes private recording metadata only after a completed job and uses an independent local display eye without another read', async () => {
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
        expect(host.querySelector('[data-verification-result="success"]')).not.toBeNull(),
    );
    expect(host.textContent).not.toContain('locally-verified-user');
    const reads = vi.mocked(WebAccess.prototype.managementRecordings).mock.calls.length;
    await click(button(host, t('adminGridShowDetails')));
    await vi.waitFor(() => expect(host.textContent).toContain('locally-verified-user'));
    await click(button(host, t('recordingRefresh')));
    expect(WebAccess.prototype.managementRecordings).toHaveBeenCalledTimes(reads);
    expect(WebAccess.prototype.openRecordingSource).toHaveBeenCalledOnce();
    expect(verifyArtifact).toHaveBeenCalledOnce();
    await click(button(host, t('adminGridHideDetails')));
    expect(host.textContent).not.toContain('locally-verified-user');
    expect(WebAccess.prototype.managementRecordings).toHaveBeenCalledTimes(reads);
});

it('cancels the encrypted recording eye without publishing private columns, starting a source job or losing the loaded page', async () => {
    vi.mocked(WebAccess.prototype.managementAuditlogs).mockResolvedValue({
        items: [{ ...source, encrypted: true }],
        next: '',
        skipped: 0,
    });
    const { flow: _flow, ...publicRow } = recording;
    vi.mocked(WebAccess.prototype.managementRecordings).mockResolvedValue({
        items: [
            {
                ...publicRow,
                format: 'becast-cbor/v1',
                encrypted: true,
                verificationScope: 'outer',
                recipientFingerprint: `SHA256:${'a'.repeat(43)}`,
                metadataUnavailable: true,
            },
        ],
        next: '',
        skipped: 0,
        total: 1,
    });
    const host = await mount(
        createElement(ArtifactCatalog, {
            access: access(),
            active: true,
            disabled: false,
            onSelect: vi.fn(),
        }),
    );
    await vi.waitFor(() => expect(button(host, `Open recording ${id}`).disabled).toBe(false));
    const reads = vi.mocked(WebAccess.prototype.managementRecordings).mock.calls.length;
    await click(button(host, t('recordingDecryptDetails')));
    const dialog = [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].find((node) =>
        node.checkVisibility({ visibilityProperty: true }),
    );
    if (!dialog) {
        throw new Error('Missing private recording options');
    }
    await click(button(dialog, t('cancel')));
    expect(host.querySelector('[role="columnheader"][data-field="user"]')).toBeNull();
    expect(button(host, `Open recording ${id}`).disabled).toBe(false);
    expect(button(host, t('recordingDecryptDetails'))).toBeDefined();
    expect(WebAccess.prototype.managementRecordings).toHaveBeenCalledTimes(reads);
    expect(WebAccess.prototype.openRecordingSource).not.toHaveBeenCalled();
    expect(verifyArtifact).not.toHaveBeenCalled();
});

it('discards an over-budget metadata index but still verifies the entire confirmed source without a retry', async () => {
    vi.spyOn(RecordingIndexBuilder.prototype, 'add').mockImplementationOnce(() => {
        throw new EvidenceError('limit');
    });
    vi.mocked(WebAccess.prototype.openRecordingSource).mockImplementation(async (auditlog) => {
        const rows = (async function* () {
            for (const [number, current] of [
                id,
                '34e34ab8-7457-4d88-a5e4-c57791775c3b',
            ].entries()) {
                yield {
                    request: { kind: 'recording' as const, auditlog, id: current },
                    image: {
                        bytes: new ArrayBuffer(3),
                        status: 200,
                        mediaType: 'application/vnd.bifroest.management-transfer.v1',
                    },
                    index: number + 1,
                    total: 2,
                    encrypted: false,
                    recipient: '',
                };
            }
        })();
        return Object.assign(rows, { closed: Promise.resolve(), cancel: vi.fn() });
    });
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
        expect(host.querySelector('[data-verification-result="success"]')).not.toBeNull(),
    );
    expect(verifyArtifact).toHaveBeenCalledTimes(2);
    expect(WebAccess.prototype.openRecordingSource).toHaveBeenCalledOnce();
    expect(host.textContent).not.toContain('locally-verified-user');
    expect(vi.mocked(verifyArtifact).mock.calls[0]?.[1]).toMatchObject({
        level: 'private',
        metadata: true,
    });
    expect(vi.mocked(verifyArtifact).mock.calls[1]?.[1]).toMatchObject({ level: 'private' });
    await click(button(host, t('recordingVerificationDetails')));
    const dialog = [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].find((node) =>
        node.checkVisibility({ visibilityProperty: true }),
    );
    expect(dialog?.textContent).toContain('metadata-limit');
    expect(dialog?.textContent).toContain(t('recordingMetadataIndexLimit'));
});

it.each(['success', 'failure'] as const)(
    'shows the %s recording verification result only as an icon and opens compact details on click',
    async (outcome) => {
        if (outcome === 'failure') {
            vi.mocked(verifyArtifact).mockRejectedValue(new EvidenceError('verification'));
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
        expect(dialog?.textContent).toContain(t('artifactServerSigner'));
        if (!dialog) {
            throw new Error('Missing result dialog');
        }
        await click(button(dialog, t('close')));
        await click(button(host, t('directServerData')));
        expect(host.querySelector('[data-verification-result]')).toBeNull();
        expect(WebAccess.prototype.managementVerifyRecordings).not.toHaveBeenCalled();
        expect(verifyArtifact).toHaveBeenCalledOnce();
        expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
        expect(WebAccess.prototype.openRecordingSource).toHaveBeenCalledOnce();
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
    await vi.waitFor(() =>
        expect(WebAccess.prototype.managementAuditEvents).toHaveBeenCalledOnce(),
    );
    expect(host.textContent).not.toContain(t('auditOverviewEncrypted'));
    expect(host.querySelector<HTMLInputElement>('input[type="checkbox"]')).toBeNull();
    await click(button(host, t('auditDecryptDetails')));
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
                      location: {
                          managementFlow: 'management',
                          page: 'auditlogs',
                          auditlog: 'default',
                      },
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
