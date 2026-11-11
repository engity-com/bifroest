import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Select, TextInput } from '../src/ui/material';

const cleanups: (() => void)[] = [];
beforeEach(() => vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true));
afterEach(async () => {
    await act(async () => {
        for (const cleanup of cleanups.splice(0)) {
            cleanup();
        }
    });
    vi.unstubAllGlobals();
});
async function render(content: ReturnType<typeof createElement>) {
    const container = document.createElement('div');
    document.body.append(container);
    const root = createRoot(container);
    cleanups.push(() => {
        root.unmount();
        container.remove();
    });
    await act(async () => root.render(content));
    return container;
}
describe('labels for filters with visible empty-value content', () => {
    it('keeps an empty selection label above its visible All statuses option', async () => {
        const container = await render(
            createElement(Select, {
                label: 'Status',
                value: '',
                onChange: () => {},
                data: [{ value: '', label: 'All statuses' }],
            }),
        );
        expect(container.querySelector('[role="combobox"]')?.textContent).toBe('All statuses');
        expect(container.querySelector('.MuiInputLabel-root')?.getAttribute('data-shrink')).toBe(
            'true',
        );
    });
    it.each(['datetime-local', 'date', 'time'])(
        'keeps an empty %s label separate from the browser date/time placeholder',
        async (type) => {
            const container = await render(
                createElement(TextInput, { label: 'From', type, value: '', onChange: () => {} }),
            );
            expect(container.querySelector('input')?.type).toBe(type);
            expect(
                container.querySelector('.MuiInputLabel-root')?.getAttribute('data-shrink'),
            ).toBe('true');
        },
    );
    it('leaves ordinary empty text inputs with their native floating-label behavior', async () => {
        const container = await render(
            createElement(TextInput, { label: 'User', value: '', onChange: () => {} }),
        );
        expect(container.querySelector('.MuiInputLabel-root')?.getAttribute('data-shrink')).toBe(
            'false',
        );
    });
});
