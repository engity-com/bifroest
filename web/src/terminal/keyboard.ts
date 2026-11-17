const terminalKeys = new Set([
    'Backspace',
    'Tab',
    'Enter',
    'Escape',
    'Insert',
    'Delete',
    'Home',
    'End',
    'PageUp',
    'PageDown',
    'ArrowUp',
    'ArrowDown',
    'ArrowLeft',
    'ArrowRight',
]);

// xterm deliberately leaves unmodified keys uncancelled in screen-reader mode.
// Text/IME must retain that behavior, but terminal function/navigation keys must
// not also invoke browser menus, caret browsing, help, scrolling or focus moves.
// Returning true keeps xterm's normal key-to-terminal-sequence translation.
export function ownTerminalKey(event: KeyboardEvent): boolean {
    if (
        !event.isComposing &&
        event.keyCode !== 229 &&
        (event.type === 'keydown' || event.type === 'keyup') &&
        (terminalKeys.has(event.key) || /^F(?:[1-9]|1[0-9]|2[0-4])$/u.test(event.key))
    ) {
        event.preventDefault();
        event.stopPropagation();
    }
    return true;
}
