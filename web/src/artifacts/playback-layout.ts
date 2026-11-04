import { fitPlaybackViewport } from './playback-view';

// Resize the presentation only. Recorded columns/rows and terminal state are
// never fitted or clamped to the browser window.
export function observePlaybackLayout(box: HTMLElement, surface: HTMLElement) {
  const screen = surface.querySelector<HTMLElement>('.xterm-screen');
  if (screen === null) {
    return { dispose() {} };
  }
  let disposed = false;
  const updateLayout = () => {
    if (disposed) {
      return;
    }
    const style = getComputedStyle(screen);
    const width = Number.parseFloat(style.width);
    const height = Number.parseFloat(style.height);
    const image = fitPlaybackViewport(width, height, box.clientWidth, box.clientHeight);
    if (image === null) {
      return;
    }
    surface.style.width = `${width}px`;
    surface.style.height = `${height}px`;
    surface.style.left = `${image.left}px`;
    surface.style.top = `${image.top}px`;
    surface.style.transform = `scale(${image.scale})`;
  };
  const observer = new ResizeObserver(updateLayout);
  observer.observe(box);
  observer.observe(screen);
  // Xterm reflects its current default background (including OSC 11/reset) on
  // the public viewport DOM. Mirror that CSS color, never parse recorded escape
  // sequences ourselves or access private terminal services.
  const viewport =
    surface.querySelector<HTMLElement>('.xterm-scrollable-element') ??
    surface.querySelector<HTMLElement>('.xterm-viewport');
  const background = new MutationObserver(() => updateBackground());
  const updateBackground = () => {
    if (!disposed && viewport !== null) {
      box.style.setProperty('--recording-background', getComputedStyle(viewport).backgroundColor);
    }
  };
  if (viewport !== null) {
    background.observe(viewport, { attributes: true, attributeFilter: ['style'] });
    updateBackground();
  }
  void document.fonts.ready.then(updateLayout);
  updateLayout();
  return {
    dispose() {
      disposed = true;
      observer.disconnect();
      background.disconnect();
      box.style.removeProperty('--recording-background');
    },
  };
}
