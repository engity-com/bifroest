interface TerminalClipboard {
    active(): boolean;
    selection(): string;
    capturePaste(): ((text: string) => void) | null;
    failed(): void;
    succeeded?(): void;
}

// Never translate copy/paste shortcuts into Ctrl+C/Ctrl+V terminal bytes.
// Clipboard access is initiated only by this explicit keyboard gesture.
export function terminalClipboardKey(event: KeyboardEvent, ports: TerminalClipboard): boolean {
    const key = event.key.toLowerCase();
    if (
        !ports.active() ||
        !event.ctrlKey ||
        !event.shiftKey ||
        event.metaKey ||
        event.altKey ||
        event.isComposing ||
        event.keyCode === 229 ||
        !['c', 'v'].includes(key)
    ) {
        return false;
    }
    event.preventDefault();
    event.stopPropagation();
    if (event.type !== 'keydown' || event.repeat) {
        return true;
    }
    try {
        if (key === 'c') {
            const selection = ports.selection();
            if (selection) {
                void navigator.clipboard
                    .writeText(selection)
                    .then(() => {
                        if (ports.active()) {
                            ports.succeeded?.();
                        }
                    })
                    .catch(() => {
                        if (ports.active()) {
                            ports.failed();
                        }
                    });
            }
        } else {
            const paste = ports.capturePaste();
            if (paste) {
                void navigator.clipboard
                    .readText()
                    .then((text) => {
                        if (!ports.active()) {
                            return;
                        }
                        if (text.length > 64 << 10) {
                            ports.failed();
                            return;
                        }
                        paste(text);
                        ports.succeeded?.();
                    })
                    .catch(() => {
                        if (ports.active()) {
                            ports.failed();
                        }
                    });
            }
        }
    } catch {
        ports.failed();
    }
    return true;
}
