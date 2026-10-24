import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { MantineProvider } from '@mantine/core';
import { useMediaQuery } from '@mantine/hooks';
import '@mantine/core/styles.css';
import './ui/app.css';
import { App } from './ui/App';
import type { LinkMetadata } from './ui/App';
import { t } from './ui/messages';
import { validateScope } from './remember/protocol';

const memoryScheme = { get: () => 'auto' as const, set() {}, subscribe() {}, unsubscribe() {}, clear() {} };

function Workspace({ metadata, title }: { metadata: LinkMetadata; title: string }) {
  const [scheme, setScheme] = useState('auto');
  const dark = useMediaQuery('(prefers-color-scheme: dark)');
  useEffect(() => { window.dispatchEvent(new CustomEvent('bifroest:ready', { detail: { version: 1 } })); }, []);
  return <MantineProvider forceColorScheme={scheme === 'auto' ? dark ? 'dark' : 'light' : scheme === 'dark' ? 'dark' : 'light'} colorSchemeManager={memoryScheme} getStyleNonce={() => document.querySelector<HTMLMetaElement>('meta[name="bifroest-nonce"]')?.content ?? ''}>
    <App metadata={metadata} title={title} scheme={scheme} onScheme={setScheme} />
  </MantineProvider>;
}

async function start() {
  const container = document.getElementById('root');
  if (container === null) return;
  try {
    const path = location.pathname;
    const scope = { origin: location.origin, slug: path === '/' ? '' : path.slice(1) };
    validateScope(scope);
    const response = await fetch(path, { headers: { Accept: 'application/json' }, credentials: 'omit', cache: 'no-store', mode: 'same-origin', redirect: 'error', signal: AbortSignal.timeout(20_000) });
    if (!response.ok || !response.headers.get('Content-Type')?.startsWith('application/json') || response.body === null) throw new Error();
    const reader = response.body.getReader(), chunks: Uint8Array[] = [];
    let length = 0;
    try {
      while (true) {
        const chunk = await reader.read(); if (chunk.done) break;
        length += chunk.value.byteLength; if (length > 64 << 10) throw new Error();
        chunks.push(chunk.value);
      }
    } finally { await reader.cancel().catch(() => undefined); reader.releaseLock(); }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as Record<string, unknown>;
    const selected = body.scope as Record<string, unknown> | null;
    if (selected === null || typeof selected !== 'object' || selected.origin !== scope.origin || selected.slug !== scope.slug || typeof body.requestUser !== 'boolean') throw new Error();
    const links = body.publishedSlugs === undefined ? [] : body.publishedSlugs;
    if (!Array.isArray(links) || links.length > 1024 || !links.every(slug => typeof slug === 'string' && /^[A-Za-z0-9]{1,64}(?:\/[A-Za-z0-9]{1,64})?$/.test(slug))) throw new Error();
    const customization = { version: 1, title: t('brand') };
    window.dispatchEvent(new CustomEvent('bifroest:configure', { detail: customization }));
    const title = typeof customization.title === 'string' && customization.title.length <= 128 ? customization.title : t('brand');
    document.title = title;
    createRoot(container).render(<Workspace metadata={{ scope, requestUser: body.requestUser, publishedSlugs: links as string[] }} title={title} />);
  } catch { container.textContent = t('loadFailed'); }
}

// Deferred classic customization files must finish before this init event. A
// module running while readyState=interactive must still wait for DOMContentLoaded.
if (document.readyState === 'complete') void start();
else document.addEventListener('DOMContentLoaded', () => { void start(); }, { once: true });
