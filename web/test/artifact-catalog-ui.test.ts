import { act, createElement, StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ArtifactCatalog } from '../src/artifacts/ArtifactCatalog';
import { AuditCatalog } from '../src/artifacts/AuditCatalog';
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
async function mount(
    initial = access(),
    active = true,
    strict = false,
    view: 'recordings' | 'auditlogs' = 'recordings',
) {
    const element = document.createElement('div');
    element.style.width = '1200px';
    document.body.append(element);
    const root = createRoot(element);
    const selected =
        vi.fn<(request: ArtifactRequest, summary?: RecordingSummary | AuditlogSummary) => void>();
    const render = async (
        options: {
            access?: WebAccess;
            active?: boolean;
            disabled?: boolean;
            selected?: ArtifactRequest;
        } = {},
    ) => {
        await act(async () => {
            const props = {
                access: initial,
                active,
                disabled: false,
                onSelect: selected,
                ...options,
            };
            const content =
                view === 'recordings'
                    ? createElement(ArtifactCatalog, props)
                    : createElement(AuditCatalog, props);
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
    it('streams auditlog-source progress and cancels without adopting a late page or borrowing recording results', async () => {
        const pending = Promise.withResolvers<Page<AuditlogSummary>>();
        vi.mocked(WebAccess.prototype.managementAuditlogs).mockImplementationOnce(
            () => pending.promise,
        );
        const app = await mount(access(), true, false, 'auditlogs');
        const call = vi.mocked(WebAccess.prototype.managementAuditlogs).mock.calls[0];
        await act(async () => call?.[2]?.({ phase: 'inventory', completed: 12, total: 22 }));
        expect(app.element.textContent).toContain(t('scanInventory'));
        expect(app.element.textContent).toContain('12 / 22');
        expect(app.element.querySelectorAll('[role="row"][data-id]')).toHaveLength(0);
        await click(button(t('artifactCatalogCancel')));
        expect(call?.[1]?.aborted).toBe(true);
        await act(async () => pending.resolve({ items: [source], next: '', skipped: 0 }));
        await vi.waitFor(() =>
            expect(app.element.textContent).toContain(t('artifactCatalogCancelled')),
        );
        expect(app.element.querySelectorAll('[role="row"][data-id]')).toHaveLength(0);
        expect(WebAccess.prototype.managementAuditlogs).toHaveBeenCalledOnce();
        expect(WebAccess.prototype.managementRecordings).not.toHaveBeenCalled();
        expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
        await click(button(t('auditRefresh')));
        await vi.waitFor(() =>
            expect(app.element.querySelectorAll('[role="row"][data-id]')).toHaveLength(1),
        );
        expect(WebAccess.prototype.managementAuditlogs).toHaveBeenCalledTimes(2);
        await act(async () => call?.[2]?.({ phase: 'inventory', completed: 22, total: 22 }));
        expect(app.element.textContent).not.toContain(t('scanInventory'));
    });
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
            expect.any(Function),
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
    it('opens the exact row through its final Actions icon or its row, never downloading on selection alone', async () => {
        const app = await mount();
        await click(button(`${t('recordingOpen')} ${row.id}`));
        expect(app.selected).toHaveBeenCalledExactlyOnceWith(
            { kind: 'recording', auditlog: row.auditlog, id: row.id },
            row,
        );
        expect([...app.element.querySelectorAll('[role="columnheader"]')].at(-1)?.textContent).toBe(
            'Actions',
        );
        const cell = app.element.querySelector<HTMLElement>(
            '[role="gridcell"][data-field="startedAt"]',
        );
        if (!cell) {
            throw new Error('Missing Recording row');
        }
        await click(cell);
        expect(app.selected).toHaveBeenCalledTimes(2);
        expect(app.selected).toHaveBeenLastCalledWith(
            { kind: 'recording', auditlog: row.auditlog, id: row.id },
            row,
        );
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
        expect(
            document.querySelector('[role="gridcell"][data-field="duration"]')?.textContent,
        ).toBe('30 min 12 s');
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
        ).toMatchObject({
            filter: { field: 'user', operator: 'contains', value: 'alice' },
            after: '',
        });
    });
    it('paginates the audit-source entry dataset without a recording-source dropdown or an implicit library read', async () => {
        vi.mocked(WebAccess.prototype.managementAuditlogs).mockResolvedValue({
            items: [source],
            next: 'bmp1.sources',
            skipped: 0,
        });
        await mount(access(), true, false, 'auditlogs');
        expect(WebAccess.prototype.managementRecordings).not.toHaveBeenCalled();
        expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
        expect(hasNamedCombobox(t('recordingSource'))).toBe(false);
        expect(button('Go to next page').disabled).toBe(false);
    });

    it('opens an explicitly selected audit source on its final source page without choosing its recording library automatically', async () => {
        vi.mocked(WebAccess.prototype.managementAuditlogs)
            .mockResolvedValueOnce({
                items: [{ ...source, name: 'audit-only', recordingEnabled: false }],
                next: 'bmp1.remaining',
                skipped: 0,
            })
            .mockResolvedValueOnce({ items: [source], next: '', skipped: 0 });
        const app = await mount(access(), true, false, 'auditlogs');
        expect(WebAccess.prototype.managementRecordings).not.toHaveBeenCalled();
        await click(button('Go to next page'));
        expect(WebAccess.prototype.managementAuditlogs).toHaveBeenCalledTimes(2);
        expect(WebAccess.prototype.managementRecordings).not.toHaveBeenCalled();
        expect(hasNamedCombobox(t('recordingSource'))).toBe(false);
        await click(button(`${t('recordingOpenAudit')} default`));
        expect(app.selected).toHaveBeenCalledExactlyOnceWith(
            { kind: 'audit', auditlog: 'default' },
            source,
        );
        expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
    });
    it('retains one skeleton grid through explicit cancellation without partial rows or automatic retry', async () => {
        let release!: (page: Page<RecordingSummary>) => void;
        vi.mocked(WebAccess.prototype.managementRecordings).mockImplementationOnce(
            () =>
                new Promise((resolve) => {
                    release = resolve;
                }),
        );
        const app = await mount();
        const grid = document.querySelector(
            `[role="grid"][aria-label="${t('recordingList')} · default"]`,
        );
        expect(grid).not.toBeNull();
        expect(button(t('artifactCatalogCancel')).disabled).toBe(false);
        expect(document.querySelector(`button[aria-label="${t('recordingRefresh')}"]`)).toBeNull();
        await click(button(t('artifactCatalogCancel')));
        await app.render({ disabled: true });
        expect(
            vi.mocked(WebAccess.prototype.managementRecordings).mock.calls[0]?.[2]?.aborted,
        ).toBe(true);
        await act(async () => release({ items: [row], next: '', skipped: 0 }));
        await app.render({ disabled: false });
        await app.render({ active: false });
        await app.render({ active: true });
        expect(
            document.querySelector(`[role="grid"][aria-label="${t('recordingList')} · default"]`),
        ).toBe(grid);
        expect(document.querySelectorAll('[role="row"][data-id]')).toHaveLength(0);
        expect(WebAccess.prototype.managementRecordings).toHaveBeenCalledTimes(1);
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
            release({
                items: [{ ...source, name: 'old-actor-private-source' }],
                next: '',
                skipped: 0,
            }),
        );
        expect(document.body.textContent).not.toContain('old-actor-private-source');
        expect(WebAccess.prototype.managementRecordings).toHaveBeenCalledTimes(1);
        expect(WebAccess.prototype.downloadArtifact).not.toHaveBeenCalled();
    });
});
