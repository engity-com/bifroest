import { isToken, object, time } from '../remember/http';
import { RememberMeError } from '../remember/protocol';
import { session } from './protocol';
import type { SessionItem } from './protocol';

export type SessionAction = 'disconnect' | 'dispose';
export interface ActionPreview { readonly action: SessionAction; readonly target: SessionItem; readonly expiresAt: string; }
export interface ActionResult { readonly action: SessionAction; readonly flow: string; readonly id: string; }

// The permission and original access are closure/private state. A dialog keeps
// this exact handle, not a row selected later or a newer actor's access object.
export class SessionActionConfirmation {
  readonly #preview: ActionPreview;
  readonly #commit: (signal?: AbortSignal) => Promise<ActionResult>;
  readonly #cancel: () => Promise<void>;
  #state: 'pending' | 'used' | 'cancelled' = 'pending';
  constructor(preview: ActionPreview, commit: (signal?: AbortSignal) => Promise<ActionResult>, cancel: () => Promise<void>) { this.#preview = preview; this.#commit = commit; this.#cancel = cancel; }
  snapshot(): ActionPreview { return this.#preview; }
  toJSON(): ActionPreview { return this.snapshot(); }
  async confirm(signal?: AbortSignal): Promise<ActionResult> {
    if (this.#state !== 'pending') throw new RememberMeError('changed');
    if (signal?.aborted) { await this.cancel(); throw new RememberMeError('cancelled'); }
    this.#state = 'used'; // Retire locally before the first possible commit byte.
    try { return await this.#commit(signal); }
    catch { throw new RememberMeError('management-unknown'); }
  }
  async cancel(): Promise<boolean> {
    if (this.#state !== 'pending') return false; // Never an undo after dispatch.
    this.#state = 'cancelled';
    try { await this.#cancel(); return true; } catch { return false; }
  }
}

export function actionPreparation(value: unknown, action: SessionAction, flow: string, id: string): { preview: ActionPreview; confirmationToken: string } {
  const result = object(value, ['version', 'status', 'confirmationToken', 'expiresAt', 'action', 'target']);
  if (result.version !== 1 || result.status !== 'confirmation-required' || result.action !== action || !isToken(result.confirmationToken, 'bmc1.')) throw new RememberMeError('unavailable');
  const target = session(result.target);
  if (target.flow !== flow || target.id !== id) throw new RememberMeError('denied');
  return { confirmationToken: result.confirmationToken, preview: Object.freeze({ action, target, expiresAt: time(result.expiresAt) }) };
}
export function actionResult(value: unknown, preview: ActionPreview): ActionResult {
  const body = object(value, ['version', 'status', 'result']), result = object(body.result, ['action', 'flow', 'id']);
  if (body.version !== 1 || body.status !== 'completed' || result.action !== preview.action || result.flow !== preview.target.flow || result.id !== preview.target.id) throw new RememberMeError('unavailable');
  return Object.freeze({ action: preview.action, flow: preview.target.flow, id: preview.target.id });
}
