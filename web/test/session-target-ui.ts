import { act } from 'react';
import { t } from '../src/ui/messages';

export async function openSessionTarget(parent: ParentNode = document): Promise<HTMLElement> {
  const pin = [...parent.querySelectorAll<HTMLButtonElement>('button')].find(
    (node) => !node.closest('[hidden]') && node.getAttribute('aria-label') === t('recordingManual'),
  );
  if (!pin) {
    throw new Error('Missing session target pin');
  }
  await act(async () => pin.click());
  const dialog = [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].find(
    (node) => node.getAttribute('aria-label') === t('recordingManual'),
  );
  if (!dialog) {
    throw new Error('Missing session target popover');
  }
  return dialog;
}
export async function sessionTargetAction(dialog: HTMLElement, label: string): Promise<void> {
  const control = [...dialog.querySelectorAll<HTMLElement>('[role="combobox"]')].find((node) =>
    (node.getAttribute('aria-labelledby') ?? '')
      .split(/\s+/u)
      .some((id) => document.getElementById(id)?.textContent === t('managementActionKind')),
  );
  if (!control) {
    throw new Error('Missing target action selector');
  }
  await act(async () =>
    control.dispatchEvent(new MouseEvent('mousedown', { button: 0, bubbles: true })),
  );
  const option = [...document.querySelectorAll<HTMLElement>('[role="option"]')].find(
    (node) => node.textContent === label,
  );
  if (!option) {
    throw new Error(`Missing target action ${label}`);
  }
  await act(async () => option.click());
}
