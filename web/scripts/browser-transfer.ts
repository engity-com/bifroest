import { createHash } from 'node:crypto';
import { appendFileSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { browserGoToolchain } from './browser-key.ts';
import { browserGoLicenses } from './go-licenses.ts';

export function buildBrowserTransfer(output: URL): void {
    const { cwd, go, version, runtimeHash, runtimeSource } = browserGoToolchain(output);
    const target = new URL('browser-transfer.wasm', output);
    go([
        'build',
        '-trimpath',
        '-ldflags=-s -w',
        '-o',
        fileURLToPath(target),
        './cmd/browser-transfer',
    ]);
    if (statSync(target).size > 8 << 20) {
        throw new Error('Browser transfer WASM exceeds the unchanged public asset limit');
    }
    const modules = browserGoLicenses(cwd, './cmd/browser-transfer');
    const project = readFileSync(join(cwd, 'LICENSES/Apache-2.0.txt'), 'utf8');
    const standard = readFileSync(
        join(cwd, 'cmd/build/third-party-licenses/BSD-3-Clause-Go-1.27.4.txt'),
        'utf8',
    );
    const notices = [
        `Bifröst browser artifact transport bridge: Apache-2.0\n${project}`,
        `${version} runtime and standard library: BSD-3-Clause\n${standard}`,
        ...modules.map(
            (entry) =>
                `${entry.module}: ${entry.license}\n${entry.files.map((file) => file.text).join('\n\n')}`,
        ),
    ].join('\n\n');
    writeFileSync(new URL('browser-transfer-licenses.txt', output), notices);
    appendFileSync(
        new URL('third-party-licenses.txt', output),
        `\n\nGo/WASM artifact transport notices\n\n${notices}`,
    );
    writeFileSync(
        new URL('browser-transfer-components.json', output),
        `${JSON.stringify(
            {
                schema: 'bifroest-browser-transfer-components-v1',
                toolchain: version,
                runtimeSHA256: runtimeHash,
                runtimeSource,
                modules: modules.map((entry) => ({
                    ...entry,
                    files: entry.files.map(({ text: _text, ...file }) => file),
                })),
                project: { module: 'github.com/engity-com/bifroest', license: 'Apache-2.0' },
                wasmSHA256: createHash('sha256').update(readFileSync(target)).digest('hex'),
            },
            null,
            2,
        )}\n`,
    );
}
