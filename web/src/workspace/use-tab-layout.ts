import { useLayoutEffect, useRef } from 'react';
import type { WorkspaceTab } from './model';

export function useTabLayout(active: number | null, tabs: readonly WorkspaceTab[]) {
    const tabList = useRef<HTMLDivElement | null>(null);
    useLayoutEffect(() => {
        const showActive = () => {
            const list = tabList.current;
            const header = list?.closest<HTMLElement>('.application-tabs');
            if (list && header) {
                const reserved = [...header.children]
                    .filter((node) => !node.contains(list))
                    .reduce((width, node) => width + node.getBoundingClientRect().width, 0);
                const gaps =
                    (Number.parseFloat(getComputedStyle(header).columnGap) || 0) *
                    Math.max(0, header.children.length - 1);
                const arrows = [...list.querySelectorAll('.MuiTabs-scrollButtons')].reduce(
                    (width, node) => width + node.getBoundingClientRect().width,
                    0,
                );
                // Available space, not intrinsic label width: short first labels must
                // not permanently constrain later, longer titles.
                const available = header.clientWidth - reserved - gaps - arrows;
                list.style.setProperty(
                    '--connection-tab-width',
                    `${Math.max(48, Math.min(320, available))}px`,
                );
            }
            if (active !== null && tabs.some((tab) => tab.id === active)) {
                document
                    .getElementById(`terminal-tab-${active}`)
                    ?.scrollIntoView({ inline: 'nearest', block: 'nearest' });
            }
        };
        showActive();
        const observer = new ResizeObserver(showActive);
        const list = tabList.current;
        if (list) {
            observer.observe(list);
            const scroller = list.querySelector('.MuiTabs-scroller');
            if (scroller) {
                observer.observe(scroller);
            }
            const header = list.closest('.application-tabs');
            if (header) {
                observer.observe(header);
            }
        }
        return () => observer.disconnect();
    }, [active, tabs]);
    return tabList;
}
