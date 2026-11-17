import { useLayoutEffect, useRef } from 'react';

export function useTabLayout() {
    const tabList = useRef<HTMLDivElement | null>(null);
    useLayoutEffect(() => {
        const updateWidth = () => {
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
        };
        // MUI owns selected-tab scrolling. Resizing must not compete with its
        // animation or snap a user browsing background tabs back to the active one.
        updateWidth();
        const observer = new ResizeObserver(updateWidth);
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
    }, []);
    return tabList;
}
