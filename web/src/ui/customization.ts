import { t } from './messages';

// Both document entries expose the same trusted operator customization hook.
export function configureBrowserTitle(): string {
    const customization = { version: 1, title: t('brand') };
    window.dispatchEvent(new CustomEvent('bifroest:configure', { detail: customization }));
    const title =
        typeof customization.title === 'string' && customization.title.length <= 128
            ? customization.title
            : t('brand');
    document.title = title;
    return title;
}

export function afterDocumentReady(start: () => void): void {
    // Deferred classic operator scripts must register their hooks first.
    if (document.readyState === 'complete') {
        start();
    } else {
        document.addEventListener('DOMContentLoaded', start, { once: true });
    }
}
