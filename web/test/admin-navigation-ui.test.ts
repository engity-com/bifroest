import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, expect, it, vi } from 'vitest';
import { WebAccess } from '../src/remember/client';
import { Http } from '../src/remember/http';
import { useAdminDetail } from '../src/ui/admin-navigation';
import { ManagementWorkspace } from '../src/ui/ManagementWorkspace';
import { useManagementNavigation } from '../src/ui/management-navigation';
import { t } from '../src/ui/messages';
import '../src/ui/app.css';

vi.mock('../src/management/channel', () => ({
  ManagementConnection: class {
    connected() {
      return true;
    }
    available() {
      return true;
    }
    disconnect() {}
  },
}));

vi.mock('../src/management/ManagementPanel', () => ({
  ManagementPanel: ({ view }: { view: string }) => {
    const navigation = useManagementNavigation();
    const selected = !!navigation?.location.id;
    useAdminDetail(
      'sessions',
      selected ? '7Xng23oeg4L1zHaZfeX6wB' : null,
      () => {},
      selected ? ['fixture-flow'] : [],
    );
    return createElement(
      'div',
      null,
      view === 'server'
        ? 'Home content'
        : createElement(
            'button',
            {
              type: 'button',
              onClick: () =>
                navigation?.navigate({
                  managementFlow: navigation.location.managementFlow,
                  page: 'sessions',
                  flow: 'fixture-flow',
                  id: '7Xng23oeg4L1zHaZfeX6wB',
                }),
            },
            'Open fixture session',
          ),
    );
  },
}));
vi.mock('../src/artifacts/ArtifactPanel', () => ({
  ArtifactPanel: ({ view }: { view: 'recordings' | 'auditlogs' }) => {
    useAdminDetail(view, null, () => {});
    return createElement('div', null, 'Recording content');
  },
}));

const cleanups: (() => void)[] = [];
afterEach(async () => {
  await act(async () => {
    for (const cleanup of cleanups.splice(0)) {
      cleanup();
    }
  });
  vi.unstubAllGlobals();
});
async function mount(width: number) {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  const container = document.createElement('div');
  container.style.width = `${width}px`;
  container.style.height = '600px';
  document.body.append(container);
  const scope = { origin: 'https://app.example.org', slug: 'Work' };
  const access = new WebAccess(
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
  const root = createRoot(container);
  cleanups.push(() => {
    root.unmount();
    container.remove();
  });
  await act(async () =>
    root.render(
      createElement(ManagementWorkspace, {
        access,
        owner: 1,
        signal: new AbortController().signal,
        active: true,
        disabled: false,
        onActionLock: vi.fn(),
        onReauthenticate: vi.fn(),
      }),
    ),
  );
  await vi.waitFor(() => expect(container.querySelector('.admin-shell')).not.toBeNull());
  return container;
}
function button(container: HTMLElement, label: string) {
  const node = [...container.querySelectorAll<HTMLButtonElement>('button,a[href]')].find(
    (node) => node.getAttribute('aria-label') === label || node.textContent === label,
  );
  if (!node) {
    throw new Error(`Missing ${label}`);
  }
  return node;
}
async function click(node: HTMLElement) {
  await act(async () => node.click());
}

it('starts at Bifröst with a persistent tab-local drawer and keeps the entire breadcrumb hierarchy', async () => {
  const container = await mount(1200);
  await vi.waitFor(() =>
    expect(container.querySelector('.admin-shell')?.getAttribute('data-admin-drawer')).toBe(
      'persistent',
    ),
  );
  expect(container.querySelector('[role="tablist"]')).toBeNull();
  const sections = [
    ...container.querySelectorAll(`nav[aria-label="${t('workspaceNavigation')}"] a[href]`),
  ];
  expect(sections).toHaveLength(4);
  expect(sections.some((node) => node.textContent === t('workspaceRecordings'))).toBe(false);
  expect(
    button(container, t('workspaceAuditlogs')).querySelector('[data-testid="FactCheckIcon"]'),
  ).not.toBeNull();
  expect(
    button(container, t('adminNavigationCollapse')).querySelector(
      '[data-testid="LeftPanelCloseIcon"]',
    ),
  ).not.toBeNull();
  const breadcrumb = () => container.querySelector(`nav[aria-label="${t('adminBreadcrumbs')}"]`);
  await vi.waitFor(() => expect(breadcrumb()?.textContent).toBe('Bifröst/Overview'));
  const rootLinks = [...(breadcrumb()?.querySelectorAll<HTMLAnchorElement>('a[href]') ?? [])];
  expect(rootLinks).toHaveLength(2);
  expect(rootLinks[1]?.getAttribute('aria-current')).toBe('page');
  expect(rootLinks.every((link) => link.href.includes('/#Work/'))).toBe(true);
  expect(
    Math.abs(
      (rootLinks[0]?.getBoundingClientRect().top ?? 0) -
        (rootLinks[1]?.getBoundingClientRect().top ?? 0),
    ),
  ).toBeLessThanOrEqual(0.5);
  expect(
    [...(breadcrumb()?.querySelectorAll('a[href]') ?? [])].some(
      (node) => node.textContent === 'Bifröst',
    ),
  ).toBe(true);
  await click(button(container, t('workspaceSessions')));
  await vi.waitFor(() => expect(breadcrumb()?.textContent).toContain('Sessions'));
  await vi.waitFor(() => expect(button(container, 'Open fixture session')).toBeDefined());
  await click(button(container, 'Open fixture session'));
  await vi.waitFor(() => expect(breadcrumb()?.textContent).toContain('7Xng23oeg4L1zHaZfeX6wB'));
  expect(breadcrumb()?.textContent).toBe('Bifröst/Sessions/fixture-flow/7Xng23oeg4L1zHaZfeX6wB');
  expect(breadcrumb()?.querySelectorAll('a[href]')).toHaveLength(4);
  expect(breadcrumb()?.querySelector('a[aria-current="page"]')?.getAttribute('href')).toContain(
    '/sessions/fixture-flow/7Xng23oeg4L1zHaZfeX6wB',
  );
  expect(breadcrumb()?.textContent).toContain('Bifröst');
  const back = [...(breadcrumb()?.querySelectorAll<HTMLButtonElement>('a[href]') ?? [])].find(
    (node) => node.textContent === 'Sessions',
  );
  if (!back) {
    throw new Error('Missing list breadcrumb');
  }
  await click(back);
  await vi.waitFor(() => expect(breadcrumb()?.textContent).not.toContain('7Xng23oeg4L1zHaZfeX6wB'));
  await click(button(container, t('adminNavigationCollapse')));
  expect(button(container, t('adminNavigationOpen')).getAttribute('aria-expanded')).toBe('false');
  await click(button(container, t('adminNavigationOpen')));
  expect(button(container, t('adminNavigationCollapse')).getAttribute('aria-expanded')).toBe(
    'true',
  );
});

it('contains a temporary drawer and backdrop inside only its own management pane', async () => {
  const first = await mount(600);
  const second = await mount(600);
  await click(button(first, t('adminNavigationOpen')));
  await vi.waitFor(() => expect(first.querySelector('.admin-drawer-backdrop')).not.toBeNull());
  const pane = first.querySelector('.admin-shell')?.getBoundingClientRect();
  const backdrop = first.querySelector('.admin-drawer-backdrop')?.getBoundingClientRect();
  if (!pane || !backdrop) {
    throw new Error('Missing pane-local modal bounds');
  }
  expect(backdrop.left).toBeGreaterThanOrEqual(pane.left);
  expect(backdrop.top).toBeGreaterThanOrEqual(pane.top);
  expect(backdrop.right).toBeLessThanOrEqual(pane.right + 1);
  expect(backdrop.bottom).toBeLessThanOrEqual(pane.bottom + 1);
  expect(button(second, t('adminNavigationOpen')).getAttribute('aria-expanded')).toBe('false');
  expect(second.getAttribute('aria-hidden')).not.toBe('true');
  const close = first.querySelector<HTMLButtonElement>('.admin-page-heading button');
  expect(close?.querySelector('[data-testid="LeftPanelCloseIcon"]')).not.toBeNull();
  if (!close) {
    throw new Error('Missing panel-close control');
  }
  await click(close);
  expect(button(first, t('adminNavigationOpen')).getAttribute('aria-expanded')).toBe('false');
});
