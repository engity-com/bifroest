import { describe, expect, it } from 'vitest';
import { ownTerminalKey } from '../src/terminal/keyboard';

describe('focused terminal key ownership without disturbing text input', () => {
  it('cancels browser defaults on function/navigation key down AND up without suppressing xterm', () => {
    for (const key of [
      'F1',
      'F7',
      'F10',
      'F12',
      'F24',
      'Tab',
      'Escape',
      'Enter',
      'Home',
      'End',
      'ArrowDown',
      'PageDown',
    ]) {
      for (const type of ['keydown', 'keyup']) {
        const event = new KeyboardEvent(type, { key, bubbles: true, cancelable: true });
        expect(ownTerminalKey(event)).toBe(true);
        expect(event.defaultPrevented).toBe(true);
      }
    }
  });
  it('leaves text, dead keys, AltGraph and IME composition to the browser/xterm input pipeline', () => {
    for (const options of [
      { key: 'a' },
      { key: 'A', shiftKey: true },
      { key: '€', ctrlKey: true, altKey: true },
      { key: 'Dead' },
      { key: 'Process', keyCode: 229 },
      { key: 'Enter', isComposing: true },
      { key: 'Enter', keyCode: 229 },
    ]) {
      const event = new KeyboardEvent('keydown', { ...options, bubbles: true, cancelable: true });
      expect(ownTerminalKey(event)).toBe(true);
      expect(event.defaultPrevented).toBe(false);
    }
  });
});
