// Bound the video to both the available inline size and the viewing pane's
// height. Do not use the growing document/card height as the height constraint.
export function observePlaybackStage(section: HTMLElement, stage: HTMLElement) {
    const bounds = section.closest<HTMLElement>('[data-playback-bounds]');
    const update = () => {
        if (document.fullscreenElement === stage) {
            return;
        }
        const viewport = window.visualViewport?.height ?? window.innerHeight;
        const style = bounds ? getComputedStyle(bounds) : null;
        const padding = style
            ? Number.parseFloat(style.paddingTop) + Number.parseFloat(style.paddingBottom)
            : 0;
        const paneHeight = bounds?.clientHeight ?? viewport;
        if (paneHeight <= 0) {
            return;
        }
        const heading = Math.max(
            0,
            stage.getBoundingClientRect().top - section.getBoundingClientRect().top,
        );
        const height = Math.max(1, Math.min(viewport, paneHeight) - padding - heading - 16);
        stage.style.maxWidth = `${(height * 16) / 9}px`;
    };
    const observer = new ResizeObserver(update);
    observer.observe(section);
    if (bounds) {
        observer.observe(bounds);
    }
    window.visualViewport?.addEventListener('resize', update);
    window.addEventListener('resize', update);
    update();
    return {
        dispose() {
            observer.disconnect();
            window.visualViewport?.removeEventListener('resize', update);
            window.removeEventListener('resize', update);
            stage.style.removeProperty('max-width');
        },
    };
}
