import { defineConfig } from 'vite';

// This is the independently testable client core, not the eventual React UI.
// Keep generated resources outside source control; Go asset embedding follows.
export default defineConfig({
  build: {
    target: 'es2022',
    outDir: '../var/webui-client-build',
    emptyOutDir: true,
    lib: { entry: 'src/remember/index.ts', formats: ['es'], fileName: 'remember' },
  },
});
