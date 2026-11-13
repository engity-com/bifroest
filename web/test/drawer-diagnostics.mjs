// Test-only init script. Keep scalar layout/ownership observations, never DOM
// text, hrefs, IDs, usernames, form values, storage or application objects.
export function installDrawerDiagnostics() {
    const events = [];
    const owners = new WeakMap();
    const watched = new WeakSet();
    let nextOwner = 0;
    let dropped = 0;
    let previous = '';
    const size = (value) => Math.max(0, Math.min(10000, Math.round(value)));
    const coordinate = (value) => Math.max(-10000, Math.min(10000, Math.round(value)));
    const layout = (node) => {
        if (!node) {
            return null;
        }
        const style = getComputedStyle(node);
        const rect = node.getBoundingClientRect();
        let hidden = false;
        let inert = false;
        let displayNone = false;
        for (let parent = node; parent; parent = parent.parentElement) {
            hidden ||= parent.hidden === true;
            inert ||= parent.inert === true;
            displayNone ||= getComputedStyle(parent).display === 'none';
        }
        return {
            width: size(rect.width),
            height: size(rect.height),
            x: coordinate(rect.x),
            y: coordinate(rect.y),
            hidden,
            inert,
            displayNone,
            visibility: ['visible', 'hidden', 'collapse'].includes(style.visibility)
                ? style.visibility
                : 'other',
            transformed: style.transform !== 'none',
        };
    };
    const sample = (event) => {
        const panes = [...document.querySelectorAll('.admin-shell')].slice(0, 6).map((shell) => {
            if (!owners.has(shell)) {
                owners.set(shell, ++nextOwner);
            }
            if (!watched.has(shell)) {
                watched.add(shell);
                resize.observe(shell);
            }
            const pane = shell.closest('[data-connection-active]');
            const toggle = shell.querySelector('.admin-page-heading button[aria-expanded]');
            const paper = shell.querySelector('.MuiDrawer-paper');
            return {
                owner: owners.get(shell),
                active: pane?.getAttribute('data-connection-active') === 'true',
                mode:
                    shell.getAttribute('data-admin-drawer') === 'persistent'
                        ? 'persistent'
                        : 'temporary',
                expanded: toggle?.getAttribute('aria-expanded') === 'true',
                disabled: toggle?.disabled === true,
                clientWidth: size(shell.clientWidth),
                shell: layout(shell),
                paper: layout(paper),
                link: layout(paper?.querySelector('nav a')),
                backdrop: shell.querySelector('.admin-drawer-backdrop') !== null,
            };
        });
        const state = JSON.stringify(panes);
        if (event === 'mutation' && state === previous) {
            return;
        }
        previous = state;
        if (events.length === 256) {
            events.shift();
            dropped++;
        }
        events.push({ event, at: Math.round(performance.now()), panes });
    };
    const resize = new ResizeObserver(() => sample('resize'));
    const mutation = new MutationObserver(() => sample('mutation'));
    mutation.observe(document, {
        subtree: true,
        childList: true,
        attributes: true,
        attributeFilter: [
            'hidden',
            'inert',
            'aria-hidden',
            'data-connection-active',
            'data-admin-drawer',
            'aria-expanded',
            'style',
            'class',
            'disabled',
        ],
    });
    for (const type of ['pointerdown', 'pointerup', 'click', 'focusin', 'keydown']) {
        document.addEventListener(
            type,
            (event) => {
                const target = event.target;
                if (!(target instanceof Element) || !target.closest('.admin-shell')) {
                    return;
                }
                const control = target.closest('.admin-page-heading button[aria-expanded]')
                    ? 'toggle'
                    : target.closest('.admin-drawer-backdrop')
                      ? 'backdrop'
                      : target.closest('.MuiDrawer-paper a')
                        ? 'link'
                        : 'other';
                sample(`${type}-${control}`); // Never key text, labels, target IDs or arbitrary event properties.
            },
            true,
        );
    }
    globalThis.bifroestDrawerDiagnostics = {
        snapshot: () => {
            sample('snapshot');
            return { events, dropped };
        },
    };
}
