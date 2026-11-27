import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFileSync, copyFileSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { browserGoLicenses } from './go-licenses.ts';
import { toolVersion } from './tool-versions.ts';

const version = `go${toolVersion('go')}`;
// Reviewed runtime content, independent of the compiler version pin. A real
// upstream runtime/license change still requires review, never a blind bypass.
const runtimeHash = '0c949f4996f9a89698e4b5c586de32249c3b69b7baadb64d220073cc04acba14';

// Build-only subprocesses. Browser actions never invoke a Go process.
export function browserGoToolchain(output: URL) {
    const cwd = fileURLToPath(new URL('../../', import.meta.url));
    const env = { ...process.env, GOOS: 'js', GOARCH: 'wasm', CGO_ENABLED: '0' };
    const go = (args: string[]): string =>
        execFileSync('go', args, { cwd, env, encoding: 'utf8', maxBuffer: 8 << 20 }).trim();
    if (go(['env', 'GOVERSION']) !== version) {
        throw new Error('Browser WASM needs the pinned Go toolchain');
    }
    // Explicit operator-supplied input for restricted development harnesses.
    // Never silently download a runtime or modify the selected toolchain.
    const source =
        process.env.BIFROEST_GO_WASM_EXEC ||
        join(go(['env', 'GOROOT']), 'lib', 'wasm', 'wasm_exec.js');
    const runtime = readFileSync(source);
    if (createHash('sha256').update(runtime).digest('hex') !== runtimeHash) {
        throw new Error('Go WASM runtime version/hash mismatch');
    }
    const approvedLicense = readFileSync(
        join(cwd, 'cmd/build/third-party-licenses/BSD-3-Clause-Go-1.27.4.txt'),
    );
    if (!readFileSync(join(go(['env', 'GOROOT']), 'LICENSE')).equals(approvedLicense)) {
        throw new Error('Go standard library license changed; review the bundled notice');
    }
    copyFileSync(source, new URL('go-wasm-exec.js', output));
    return {
        cwd,
        go,
        version,
        runtimeHash,
        runtimeSource: process.env.BIFROEST_GO_WASM_EXEC
            ? 'explicit operator-provided runtime override'
            : 'MISE-selected GOROOT/lib/wasm/wasm_exec.js',
    };
}

export function buildBrowserKey(output: URL): void {
    const { cwd, go, version, runtimeHash, runtimeSource } = browserGoToolchain(output);
    const target = new URL('browser-key.wasm', output);
    go(['build', '-trimpath', '-ldflags=-s -w', '-o', fileURLToPath(target), './cmd/browser-key']);
    if (statSync(target).size > 8 << 20) {
        throw new Error('Browser key WASM exceeds public asset bound');
    }
    const inventory = browserGoLicenses(cwd, './cmd/browser-key');
    const modules = inventory.map(({ module }) => module);
    const license = readFileSync(
        join(cwd, 'cmd/build/third-party-licenses/BSD-3-Clause-Go-1.27.4.txt'),
        'utf8',
    );
    const moduleNotices = inventory
        .map(
            ({ module, license, files }) =>
                `${module}\nLicense: ${license}\n${files.map((file) => file.text).join('\n\n')}`,
        )
        .join('\n\n');
    writeFileSync(
        new URL('browser-key-components.json', output),
        `${JSON.stringify(
            {
                schema: 'bifroest-browser-key-components-v1',
                toolchain: version,
                runtimeSHA256: runtimeHash,
                runtimeSource,
                modules,
                moduleLicenses: Object.fromEntries(
                    inventory.map(({ module, license }) => [module, license]),
                ),
                externalLicense: [
                    ...new Set(inventory.flatMap(({ license }) => license.split(' AND '))),
                ]
                    .sort()
                    .join(' AND '),
                project: { module: 'github.com/engity-com/bifroest', license: 'Apache-2.0' },
                wasmSHA256: createHash('sha256').update(readFileSync(target)).digest('hex'),
            },
            null,
            2,
        )}\n`,
    );
    const projectLicense = readFileSync(join(cwd, 'LICENSES/Apache-2.0.txt'), 'utf8');
    const notices = `Bifröst browser key bridge/core: Apache-2.0\n${projectLicense}\n\n${version} runtime and standard library\n${modules.join('\n')}\n\n${license}\n\n${moduleNotices}`;
    writeFileSync(new URL('browser-key-licenses.txt', output), notices);
    appendFileSync(
        new URL('third-party-licenses.txt', output),
        `\n\nGo/WASM browser-key component notices\n\n${notices}`,
    );
}
