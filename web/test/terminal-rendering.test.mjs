import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

test('WebGL draws continuous terminal cells and box lines at fractional display scales', async (t) => {
    // Deterministic software GPU in the isolated test browser only. Production
    // still uses the user's ordinary browser/GPU policy and a DOM fallback.
    for (const scale of [1, 1.25, 1.5, 2]) {
        await t.test(`device scale ${scale}`, async () => {
            // CDP's deviceScaleFactor emulation can disagree with the native
            // ResizeObserver device-pixel box. Scale the browser process itself and
            // disable viewport emulation so the GPU and observer see the same DPI.
            const browser = await chromium.launch({
                headless: true,
                args: ['--enable-unsafe-swiftshader', `--force-device-scale-factor=${scale}`],
            });
            const context = await browser.newContext({ viewport: null });
            try {
                const page = await context.newPage();
                await page.setContent(
                    '<style>body{margin:0;font:14px/1.5 system-ui;letter-spacing:.00938em}*{box-sizing:border-box}</style><div id="terminal"></div>',
                );
                for (const path of ['@xterm/xterm/css/xterm.css']) {
                    await page.addStyleTag({
                        path: fileURLToPath(new URL(`../node_modules/${path}`, import.meta.url)),
                    });
                }
                for (const path of [
                    '@xterm/xterm/lib/xterm.js',
                    '@xterm/addon-webgl/lib/addon-webgl.js',
                ]) {
                    await page.addScriptTag({
                        path: fileURLToPath(new URL(`../node_modules/${path}`, import.meta.url)),
                    });
                }
                const result = await page.evaluate(async () => {
                    const terminal = new window.Terminal({
                        cols: 20,
                        rows: 12,
                        fontSize: 14,
                        fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace',
                        customGlyphs: true,
                        theme: { foreground: '#ffffff', background: '#3465a4' },
                    });
                    terminal.open(document.getElementById('terminal'));
                    terminal.loadAddon(new window.WebglAddon.WebglAddon(true));
                    await document.fonts.ready;
                    await new Promise((resolve) =>
                        terminal.write(
                            `\x1b[37;44m${Array(12).fill('│        ').join('\r\n')}`,
                            resolve,
                        ),
                    );
                    // Parsing completion is not a GPU paint acknowledgement. Request and
                    // await the actual xterm render before inspecting its framebuffer.
                    await new Promise((resolve) => {
                        const rendered = terminal.onRender(() => {
                            rendered.dispose();
                            resolve();
                        });
                        terminal.refresh(0, terminal.rows - 1);
                    });
                    const canvas = document.querySelector(
                        '.xterm-screen canvas:not(.xterm-link-layer)',
                    );
                    const gl = canvas?.getContext('webgl2');
                    if (!gl) {
                        throw new Error(
                            'The pixel regression requires an actual WebGL renderer, not a silently skipped DOM fallback',
                        );
                    }
                    const pixels = new Uint8Array(canvas.width * canvas.height * 4);
                    gl.finish();
                    gl.readPixels(
                        0,
                        0,
                        canvas.width,
                        canvas.height,
                        gl.RGBA,
                        gl.UNSIGNED_BYTE,
                        pixels,
                    );
                    let continuousLine = 0;
                    for (let x = 0; x < canvas.width / terminal.cols; x++) {
                        let filled = 0;
                        for (let y = 0; y < canvas.height; y++) {
                            const offset = (y * canvas.width + x) * 4;
                            if (
                                pixels[offset] > 160 &&
                                pixels[offset + 1] > 160 &&
                                pixels[offset + 2] > 160
                            ) {
                                filled++;
                            }
                        }
                        continuousLine = Math.max(continuousLine, filled);
                    }
                    let backgroundHoles = 0;
                    const x = Math.floor((canvas.width / terminal.cols) * 3);
                    for (let y = 0; y < canvas.height; y++) {
                        const offset = (y * canvas.width + x) * 4;
                        if (pixels[offset + 2] < 100 || pixels[offset + 3] !== 255) {
                            backgroundHoles++;
                        }
                    }
                    const result = {
                        scale: devicePixelRatio,
                        cssHeight: canvas.getBoundingClientRect().height,
                        height: canvas.height,
                        continuousLine,
                        backgroundHoles,
                        error: gl.getError(),
                    };
                    terminal.dispose();
                    return result;
                });
                assert.equal(result.scale, scale);
                assert.equal(
                    result.height,
                    Math.round(result.cssHeight * scale),
                    'native canvas pixel dimensions must agree with the actual display scale',
                );
                assert.equal(result.error, 0);
                assert.equal(
                    result.continuousLine,
                    result.height,
                    'vertical box glyphs must fill every physical pixel row across all terminal rows',
                );
                assert.equal(
                    result.backgroundHoles,
                    0,
                    'background cells must not have horizontal seams at fractional scaling',
                );
            } finally {
                await context.close();
                await browser.close();
            }
        });
    }
});
