import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import { buildBrowserEvidence } from './scripts/browser-evidence.mjs';
import { buildBrowserKey } from './scripts/browser-key.mjs';
import { buildBrowserTransfer } from './scripts/browser-transfer.mjs';
import { writeFrontendNotices } from './scripts/frontend-notices.mjs';
import { xtermDocumentPlugin } from './scripts/xterm-document.mjs';

const output = new URL('../pkg/webui/assets/', import.meta.url);
const marker = readFileSync(new URL('README.txt', output));
const xtermVersion = JSON.parse(
  readFileSync(new URL('./node_modules/@xterm/xterm/package.json', import.meta.url), 'utf8'),
).version as string;

// Vite 8's native Oxc/Rolldown JSX pipeline; no Webpack/Babel build chain.
export default defineConfig({
  base: '/_bifroest/files/',
  build: {
    target: 'es2022',
    outDir: '../pkg/webui/assets',
    emptyOutDir: true,
    // Speculative shared-chunk fetches must not crowd out ordered operator
    // scripts under the server's existing per-peer admission budget.
    modulePreload: false,
    rolldownOptions: {
      input: {
        index: fileURLToPath(new URL('index.html', import.meta.url)),
        'browser-key-worker': fileURLToPath(new URL('src/login/key-worker.ts', import.meta.url)),
        'browser-transfer-worker': fileURLToPath(
          new URL('src/artifacts/transfer-worker.ts', import.meta.url),
        ),
        'browser-evidence-worker': fileURLToPath(
          new URL('src/artifacts/evidence-worker.ts', import.meta.url),
        ),
      },
      output: {
        entryFileNames: (chunk) =>
          ['browser-key-worker', 'browser-transfer-worker', 'browser-evidence-worker'].includes(
            chunk.name,
          )
            ? `${chunk.name}.js`
            : 'assets/[name]-[hash].js',
      },
      onwarn(warning, handler) {
        // This bundle is client-only, not a React Server Components boundary.
        if (warning.code === 'MODULE_LEVEL_DIRECTIVE' && warning.message.includes('use client')) {
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
      closeBundle() {
        mkdirSync(output, { recursive: true });
        writeFileSync(new URL('README.txt', output), marker);
        writeFrontendNotices(output);
        buildBrowserKey(output);
        buildBrowserTransfer(output);
        buildBrowserEvidence(output);
      },
    },
  ],
});
