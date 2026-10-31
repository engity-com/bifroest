import type { Terminal } from '@xterm/xterm';
import { describe, expect, it, vi } from 'vitest';
import { installTerminalRenderer } from '../src/terminal/renderer';

function fixture() {
  let loss: (() => void) | undefined;
  const dispose = vi.fn();
  const unlisten = vi.fn();
  class WebglAddon {
    onContextLoss(callback: () => void) {
      loss = callback;
      return { dispose: unlisten };
    }
    dispose = dispose;
    activate() {}
    clearTextureAtlas() {}
    onChangeTextureAtlas(_callback: (canvas: HTMLCanvasElement) => void) {
      return { dispose: unlisten };
    }
    onAddTextureAtlasCanvas = this.onChangeTextureAtlas;
    onRemoveTextureAtlasCanvas = this.onChangeTextureAtlas;
  }
  const loadAddon = vi.fn();
  const terminal = { loadAddon } as unknown as Terminal;
  const container = document.createElement('section');
  return {
    module: { WebglAddon },
    terminal,
    container,
    loadAddon,
    dispose,
    unlisten,
    lose: () => loss?.(),
  };
}
async function settle() {
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

describe('owned terminal renderer lifecycle, no execution/identity transitions', () => {
  it('uses WebGL when available and retires it exactly once on context loss', async () => {
    const f = fixture();
    const renderer = installTerminalRenderer(f.terminal, f.container, async () => f.module);
    await settle();
    expect(f.container.dataset.terminalRenderer).toBe('webgl');
    expect(f.loadAddon).toHaveBeenCalledOnce();
    f.lose();
    expect(f.container.dataset.terminalRenderer).toBe('dom');
    expect(f.dispose).toHaveBeenCalledOnce();
    expect(f.unlisten).toHaveBeenCalledOnce();
    renderer.dispose();
    expect(f.dispose).toHaveBeenCalledOnce();
  });
  it('stays functional without WebGL or when activation fails', async () => {
    for (const missing of [false, true]) {
      const f = fixture();
      f.loadAddon.mockImplementation(() => {
        throw new Error('GPU unavailable');
      });
      const renderer = installTerminalRenderer(f.terminal, f.container, async () => {
        if (missing) {
          throw new Error('module unavailable');
        }
        return f.module;
      });
      await settle();
      expect(f.container.dataset.terminalRenderer).toBe('dom');
      expect(f.dispose).toHaveBeenCalledTimes(missing ? 0 : 1);
      renderer.dispose();
    }
  });
  it('never activates a late import after the owning terminal has been closed', async () => {
    const f = fixture();
    let complete: ((module: typeof f.module) => void) | undefined;
    const module = new Promise<typeof f.module>((resolve) => {
      complete = resolve;
    });
    const renderer = installTerminalRenderer(f.terminal, f.container, () => module);
    renderer.dispose();
    complete?.(f.module);
    await settle();
    expect(f.loadAddon).not.toHaveBeenCalled();
  });
});
