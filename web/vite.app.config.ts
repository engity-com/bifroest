import { defineConfig } from 'vite';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { writeFrontendNotices } from './scripts/frontend-notices.mjs';

const output = new URL('../pkg/webui/assets/', import.meta.url);
const marker = readFileSync(new URL('README.txt', output));

// Vite 8's native Oxc/Rolldown JSX pipeline; no Webpack/Babel build chain.
export default defineConfig({
  base: '/_bifroest/files/',
  build: {
    target: 'es2022', outDir: '../pkg/webui/assets', emptyOutDir: true,
    rolldownOptions: { onwarn(warning, handler) {
      // This bundle is client-only, not a React Server Components boundary.
      if (warning.code === 'MODULE_LEVEL_DIRECTIVE' && warning.message.includes('use client')) return;
      handler(warning);
    } },
  },
  plugins: [{ name: 'retain-embed-marker', closeBundle() {
    mkdirSync(output, { recursive: true });
    writeFileSync(new URL('README.txt', output), marker);
    writeFrontendNotices(output);
  } }],
});
