import { createHash } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { browserGoToolchain } from './browser-key.ts';
import { browserGoLicenses } from './go-licenses.ts';

export function buildBrowserEvidence(output: URL): void {
    const { cwd, go, version, runtimeHash, runtimeSource } = browserGoToolchain(output);
    const directory = join(cwd, 'var', 'webui-evidence-build');
    mkdirSync(directory, { recursive: true });
    const target = join(directory, 'browser-evidence.wasm');
    go(['build', '-trimpath', '-ldflags=-s -w', '-o', target, './cmd/browser-evidence']);
    const raw = readFileSync(target);
    if (raw.length > 24 << 20) {
        throw new Error('Browser evidence WASM exceeds its uncompressed worker bound');
    }
    const compressed = gzipSync(raw, { level: 9 });
    if (compressed.length > 8 << 20) {
        throw new Error('Compressed browser evidence exceeds the unchanged asset bound');
    }
    writeFileSync(new URL('browser-evidence.wasm.gz', output), compressed);
    const entries = browserGoLicenses(cwd, './cmd/browser-evidence');
    const notices = [
        `Bifröst client-only evidence bridge/core: Apache-2.0\n${readFileSync(join(cwd, 'LICENSES/Apache-2.0.txt'), 'utf8')}`,
        `${version} runtime/standard library: BSD-3-Clause\n${readFileSync(join(cwd, 'cmd/build/third-party-licenses/BSD-3-Clause-Go-1.27.4.txt'), 'utf8')}`,
        ...entries.map(
            (entry) =>
                `${entry.module}\nLicenses: ${entry.license}\n${entry.files.map((file) => `${file.path}\n${file.text}`).join('\n\n')}`,
        ),
    ].join('\n\n');
    writeFileSync(new URL('browser-evidence-licenses.txt', output), notices);
    appendFileSync(
        new URL('third-party-licenses.txt', output),
        `\n\nGo/WASM client evidence notices\n\n${notices}`,
    );
    writeFileSync(
        new URL('browser-evidence-components.json', output),
        `${JSON.stringify(
            {
                schema: 'bifroest-browser-evidence-components-v1',
                toolchain: version,
                runtimeSHA256: runtimeHash,
                runtimeSource,
                compression: 'gzip',
                rawBytes: raw.length,
                compressedBytes: compressed.length,
                wasmSHA256: createHash('sha256').update(raw).digest('hex'),
                compressedSHA256: createHash('sha256').update(compressed).digest('hex'),
                modules: entries.map((entry) => ({
                    ...entry,
                    files: entry.files.map(({ text: _text, ...file }) => file),
                })),
                project: { module: 'github.com/engity-com/bifroest', license: 'Apache-2.0' },
            },
            null,
            2,
        )}\n`,
    );
}
