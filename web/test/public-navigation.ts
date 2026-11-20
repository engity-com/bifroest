import type { Page } from 'playwright';

// Docker can change the runner's interfaces while Chromium opens its initial
// document. Only retry that public GET, never login/API/terminal operations.
export async function publicNavigation(page: Pick<Page, 'goto'>, target: string) {
    const url = new URL(target);
    if (
        url.protocol !== 'https:' ||
        url.pathname !== '/' ||
        url.username ||
        url.password ||
        url.search ||
        target.includes('?')
    ) {
        throw new Error('Expected a public HTTPS root document');
    }
    const deadline = Date.now() + 30_000;
    try {
        return await page.goto(target, { timeout: 30_000 });
    } catch (error) {
        if (
            !(error instanceof Error) ||
            !error.message.includes('net::ERR_NETWORK_CHANGED') ||
            Date.now() >= deadline
        ) {
            throw error;
        }
        return page.goto(target, { timeout: Math.max(1, deadline - Date.now()) });
    }
}
