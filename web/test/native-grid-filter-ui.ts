import { act } from 'react';

export async function nativeColumnFilter(
  parent: ParentNode,
  columnLabel: string,
  value: string,
): Promise<void> {
  const trigger = [...parent.querySelectorAll<HTMLButtonElement>('button')].find(
    (node) => !node.closest('[hidden]') && node.getAttribute('aria-label') === 'Filters',
  );
  if (!trigger) {
    throw new Error('Missing native Filters control');
  }
  await act(async () => trigger.click());
  const column = document.querySelector<HTMLElement>(
    '.MuiDataGrid-filterFormColumnInput [role="combobox"]',
  );
  if (!column) {
    throw new Error('Missing native filter column selector');
  }
  await act(async () => {
    column.dispatchEvent(new MouseEvent('mousedown', { button: 0, bubbles: true }));
  });
  const option = [...document.querySelectorAll<HTMLElement>('[role="option"]')].find(
    (node) => node.textContent === columnLabel,
  );
  if (!option) {
    throw new Error(`Missing native filter column ${columnLabel}`);
  }
  await act(async () => option.click());
  const input = document.querySelector<HTMLInputElement>('input[placeholder="Filter value"]');
  if (!input) {
    throw new Error('Missing native filter value input');
  }
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

export async function closeNativeFilter(parent: ParentNode): Promise<void> {
  const trigger = [...parent.querySelectorAll<HTMLButtonElement>('button')].find(
    (node) => !node.closest('[hidden]') && node.getAttribute('aria-label') === 'Filters',
  );
  if (!trigger) {
    throw new Error('Missing native Filters control');
  }
  await act(async () => trigger.click());
}
