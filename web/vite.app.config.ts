import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import { buildBrowserEvidence } from './scripts/browser-evidence.ts';
import { buildBrowserKey } from './scripts/browser-key.ts';
import type { BrowserInputs } from './scripts/browser-release.ts';
import { captureBrowserInputs, writeBrowserRelease } from './scripts/browser-release.ts';
import { buildBrowserTransfer } from './scripts/browser-transfer.ts';
import { writeFrontendNotices } from './scripts/frontend-notices.ts';
import { xtermDocumentPlugin } from './scripts/xterm-document.ts';

const output = new URL('../pkg/webui/assets/', import.meta.url);
const marker = readFileSync(new URL('README.txt', output));
let browserInputs: BrowserInputs | undefined;
const xtermVersion = JSON.parse(
    readFileSync(new URL('./node_modules/@xterm/xterm/package.json', import.meta.url), 'utf8'),
).version as string;

// Vite 8's native Oxc/Rolldown JSX pipeline; no Webpack/Babel build chain.
export default defineConfig({
    base: '/assets/',
    build: {
        target: 'es2022',
        outDir: '../pkg/webui/assets',
        assetsDir: '',
        emptyOutDir: true,
        // Speculative shared-chunk fetches must not crowd out ordered operator
        // scripts under the server's existing per-peer admission budget.
        modulePreload: false,
        rolldownOptions: {
            input: {
                index: fileURLToPath(new URL('index.html', import.meta.url)),
                login: fileURLToPath(new URL('login.html', import.meta.url)),
                'browser-key-worker': fileURLToPath(
                    new URL('src/login/key-worker.ts', import.meta.url),
                ),
                'browser-transfer-worker': fileURLToPath(
                    new URL('src/artifacts/transfer-worker.ts', import.meta.url),
                ),
                'browser-evidence-worker': fileURLToPath(
                    new URL('src/artifacts/evidence-worker.ts', import.meta.url),
                ),
            },
            output: {
                // Bound the initial ESM dependency fan-out without increasing admission
                // limits or duplicating actor/key contexts across entry points.
                codeSplitting: {
                    groups: [
                        {
                            // Split only the startup UI runtimes, not lazy-only views.
                            // Leave room for the protocol and bundler helpers inside
                            // the existing four-file initial dependency budget.
                            name: 'ui-runtime',
                            test: /[/\\]node_modules[/\\](?:(?:react|react-dom|scheduler)|@emotion[/\\][^/\\]+)[/\\]/,
                            tags: ['$initial'],
                            priority: 20,
                        },
                        {
                            name: 'browser-protocol',
                            test: /[/\\]src[/\\](?:remember[/\\]|login[/\\]diagnostic\.ts$|artifacts[/\\]evidence-protocol\.ts$)/,
                        },
                    ],
                },
                entryFileNames: (chunk) =>
                    [
                        'browser-key-worker',
                        'browser-transfer-worker',
                        'browser-evidence-worker',
                    ].includes(chunk.name)
                        ? `${chunk.name}.js`
                        : '[name]-[hash].js',
            },
            onwarn(warning, handler) {
                // This bundle is client-only, not a React Server Components boundary.
                if (
                    warning.code === 'MODULE_LEVEL_DIRECTIVE' &&
                    warning.message.includes('use client')
                ) {
                    return;
                }
                handler(warning);
            },
        },
    },
    plugins: [
        xtermDocumentPlugin(xtermVersion),
        {
            name: 'retain-embed-marker',
            buildStart() {
                if (!process.env.BIFROEST_GO_WASM_EXEC) {
                    browserInputs = captureBrowserInputs();
                }
            },
            closeBundle() {
                mkdirSync(output, { recursive: true });
                writeFileSync(new URL('README.txt', output), marker);
                writeFrontendNotices(output);
                buildBrowserKey(output);
                buildBrowserTransfer(output);
                buildBrowserEvidence(output);
                // Explicit development runtimes remain usable, never release-eligible.
                if (!process.env.BIFROEST_GO_WASM_EXEC) {
                    if (browserInputs === undefined) {
                        throw new Error('Browser input snapshot unavailable');
                    }
                    writeBrowserRelease(output, undefined, browserInputs);
                }
            },
        },
    ],
});
