import type { IDisposable, Terminal } from '@xterm/xterm';

type WebglModule = typeof import('@xterm/addon-webgl');

// The DOM renderer remains a supported fallback, not a failed execution. GPU
// setup/context loss must never reconnect, replace an actor, or replay input.
export function installTerminalRenderer(
    terminal: Terminal,
    container: HTMLElement,
    load: () => Promise<WebglModule> = () => import('@xterm/addon-webgl'),
): IDisposable {
    let disposed = false;
    let addon: InstanceType<WebglModule['WebglAddon']> | null = null;
    let lost: IDisposable | undefined;
    container.dataset.terminalRenderer = 'dom';
    const fallback = () => {
        lost?.dispose();
        lost = undefined;
        const previous = addon;
        addon = null;
        try {
            previous?.dispose();
        } catch {
            /* Already-lost contexts may be disposed. */
        }
        if (!disposed) {
            container.dataset.terminalRenderer = 'dom';
        }
    };
    void Promise.resolve()
        .then(load)
        .then((module) => {
            if (disposed) {
                return;
            }
            addon = new module.WebglAddon();
            lost = addon.onContextLoss(fallback);
            terminal.loadAddon(addon);
            container.dataset.terminalRenderer = 'webgl';
        })
        .catch(fallback);
    return {
        dispose() {
            disposed = true;
            fallback();
        },
    };
}
