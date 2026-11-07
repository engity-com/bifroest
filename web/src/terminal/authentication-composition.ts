import type { LoginStep } from '../login/interactive';

// xterm displays preedit before onData and commits compositionend on a timer.
// Pin that entire native gesture to one prompt. An answer/prompt change while
// it is still active/settling is ambiguous and cancels this login, not the
// previous shell. No new prompt may inherit the old gesture or its echo flag.
export function protectAuthenticationComposition(
  surface: HTMLElement,
  current: () => LoginStep | null,
  invalid: () => void,
) {
  let owner: LoginStep | null = null;
  let active = false;
  let settling = false;
  let disposed = false;
  let retired = false;
  let epoch = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const pending = () => active || settling;
  const check = () => {
    if (retired || disposed) {
      return false;
    }
    if (pending() && owner !== current()) {
      retired = true;
      invalid();
      return false;
    }
    return true;
  };
  const start = (event: CompositionEvent) => {
    if (!check()) {
      event.stopImmediatePropagation();
      return;
    }
    if (current() === null) {
      retired = true;
      event.stopImmediatePropagation();
      invalid();
      return;
    }
    owner = current();
    active = true;
    epoch++;
  };
  const protect = (event: CompositionEvent) => {
    if (!(event.target instanceof HTMLTextAreaElement)) {
      return;
    }
    const valid = check();
    if (valid && pending() && owner?.kind === 'prompt' && owner.echo) {
      return;
    }
    if (!event.data) {
      return; // The sanitized update still advances xterm's offsets.
    }
    event.stopImmediatePropagation();
    event.target.dispatchEvent(
      new CompositionEvent('compositionupdate', { bubbles: true, data: '' }),
    );
  };
  const end = (event: CompositionEvent) => {
    if (!pending() || !check()) {
      event.stopImmediatePropagation();
      return;
    }
    active = false;
    settling = true;
    epoch++;
  };
  const afterEnd = () => {
    if (disposed || !settling) {
      return;
    }
    const generation = epoch;
    // This BUBBLE listener runs after xterm's target listener registered its
    // commit timer. A microtask from capture is NOT sufficient for native events.
    clearTimeout(timer);
    timer = setTimeout(() => {
      if (!disposed && epoch === generation && !active) {
        settling = false;
        owner = null;
      }
    }, 0);
  };
  surface.addEventListener('compositionstart', start, true);
  surface.addEventListener('compositionupdate', protect, true);
  surface.addEventListener('compositionend', end, true);
  surface.addEventListener('compositionend', afterEnd);
  return {
    pending,
    check,
    dispose() {
      disposed = true;
      clearTimeout(timer);
      owner = null;
      active = false;
      settling = false;
      surface.removeEventListener('compositionstart', start, true);
      surface.removeEventListener('compositionupdate', protect, true);
      surface.removeEventListener('compositionend', end, true);
      surface.removeEventListener('compositionend', afterEnd);
    },
  };
}
