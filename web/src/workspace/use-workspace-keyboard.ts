import { useEffect } from 'react';
import { adjustTerminalFontSize, terminalZoomKey } from '../ui/terminal-font';
import type { WorkspaceBoundary } from './contracts';
import type { WorkspaceController } from './controller';
import { keyboardAvailable } from './policy';

// Only this DOM adapter interprets keyboard/wheel events. Application commands
// recheck their own guards, so a queued event cannot bypass a new owner lock.
export function useWorkspaceKeyboard(controller: WorkspaceController, boundary: WorkspaceBoundary) {
    useEffect(() => {
        const available = () => keyboardAvailable(controller.getSnapshot(), boundary);
        const key = (event: KeyboardEvent) => {
            if (
                !available() ||
                event.defaultPrevented ||
                event.isComposing ||
                event.altKey ||
                event.metaKey ||
                !event.ctrlKey ||
                [
                    ...document.querySelectorAll<HTMLElement>(
                        '[role="dialog"],[role="menu"],[role="listbox"]',
                    ),
                ].some((element) => element.checkVisibility({ visibilityProperty: true }))
            ) {
                return;
            }
            const state = controller.getSnapshot();
            const selected = state.tabs.find((tab) => tab.id === boundary.activeView);
            if (event.key === 'Tab') {
                if (state.tabs.length < 2) {
                    return;
                }
                event.preventDefault();
                event.stopPropagation();
                controller.cycle(event.shiftKey);
                return;
            }
            if (
                selected?.kind === 'management' &&
                event.key.toLowerCase() === 'd' &&
                !event.shiftKey &&
                !(
                    event.target instanceof Element &&
                    event.target.closest(
                        'input,textarea,select,[contenteditable]:not([contenteditable="false"]),[role="textbox"]',
                    )
                )
            ) {
                event.preventDefault();
                event.stopPropagation();
                controller.closeManagementShortcut(selected.id);
                return;
            }
            const zoom = terminalZoomKey(event);
            if (selected?.kind === 'terminal' && zoom) {
                event.preventDefault();
                event.stopPropagation();
                adjustTerminalFontSize(zoom);
            }
        };
        const wheel = (event: WheelEvent) => {
            if (
                !available() ||
                !event.ctrlKey ||
                event.deltaY === 0 ||
                !(
                    event.target instanceof Element &&
                    event.target.closest('[data-connection-active="true"] .terminal-surface')
                )
            ) {
                return;
            }
            event.preventDefault();
            event.stopPropagation();
            adjustTerminalFontSize(event.deltaY < 0 ? 1 : -1);
        };
        window.addEventListener('keydown', key, true);
        window.addEventListener('wheel', wheel, { capture: true, passive: false });
        return () => {
            window.removeEventListener('keydown', key, true);
            window.removeEventListener('wheel', wheel, true);
        };
    }, [controller, boundary]);
}
