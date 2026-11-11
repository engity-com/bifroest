import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
    cpSync,
    mkdtempSync,
    readFileSync,
    rmSync,
    symlinkSync,
    unlinkSync,
    writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
    type BrowserManifest,
    captureBrowserInputs,
    type KeyComponents,
    type WasmComponents,
    writeBrowserRelease,
} from '../scripts/browser-release.ts';
import { browserGoLicenses } from '../scripts/go-licenses.ts';
import { required } from './required.ts';

const output = fileURLToPath(new URL('../../pkg/webui/assets/', import.meta.url));
const hash = (bytes: string | Uint8Array) => createHash('sha256').update(bytes).digest('hex');

function staticJavaScriptGraph(entry: string): Set<string> {
    const visited = new Set<string>();
    function visit(file: string) {
        if (visited.has(file)) {
            return;
        }
        visited.add(file);
        const text = readFileSync(join(output, file), 'utf8');
        for (const match of text.matchAll(
            /(?:from|import)\s*["'](\.\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+\.js)["']/gu,
        )) {
            visit(join(dirname(file), required(match[1])));
        }
    }
    visit(entry);
    return visited;
}

test('initial JavaScript graph fits the existing four-worker admission budget without eager xterm or grid loading', () => {
    const html = readFileSync(join(output, 'index.html'), 'utf8');
    const entry = /src="\/_bifroest\/files\/(assets\/[A-Za-z0-9_-]+\.js)"/u.exec(html)?.[1];
    assert(entry, 'built document must name its same-origin module entry');
    const visited = staticJavaScriptGraph(entry);
    assert(visited.size <= 4, `initial module graph must stay bounded: ${[...visited].join(', ')}`);
    assert(
        [...visited].every(
            (file) => !/(?:xterm|AdminDataGrid|ArtifactPanel|ManagementPanel)-/u.test(file),
        ),
        'heavy views remain explicit lazy imports',
    );
});

test('production JavaScript chunks stay below 500 kB without hiding Vite size warnings', () => {
    const manifest = JSON.parse(
        readFileSync(join(output, 'browser-build.json'), 'utf8'),
    ) as BrowserManifest;
    for (const asset of manifest.assets.filter((asset) => asset.name.endsWith('.js'))) {
        const bytes = readFileSync(join(output, asset.name)).length;
        assert(
            bytes <= 500_000,
            `${asset.name} exceeds the 500 kB JavaScript chunk budget: ${bytes} bytes`,
        );
    }
});

test('worker dependency graphs never pull in the application or UI runtime', () => {
    for (const worker of [
        'browser-key-worker.js',
        'browser-transfer-worker.js',
        'browser-evidence-worker.js',
    ]) {
        const graph = staticJavaScriptGraph(worker);
        assert(
            [...graph].some((file) => /browser-protocol-[A-Za-z0-9_-]+\.js$/u.test(file)),
            `${worker} must include its actual shared protocol dependencies`,
        );
        assert(
            [...graph].every(
                (file) =>
                    !/(?:ui-runtime|index|xterm|AdminDataGrid|ArtifactPanel|ManagementPanel)-/u.test(
                        file,
                    ),
            ),
            `${worker} must stay independent of the DOM/UI runtime: ${[...graph].join(', ')}`,
        );
    }
});

for (const entry of ['browser-key', 'browser-transfer', 'browser-evidence']) {
    test(`${entry} notices include the actual dependency versions and their collected license texts`, () => {
        const root = fileURLToPath(new URL('../../', import.meta.url));
        const graph = execFileSync(
            'go',
            [
                'list',
                '-deps',
                '-f',
                '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}}{{end}}{{end}}',
                `./cmd/${entry}`,
            ],
            {
                cwd: root,
                env: { ...process.env, GOOS: 'js', GOARCH: 'wasm', CGO_ENABLED: '0' },
                encoding: 'utf8',
            },
        );
        const expected = [...new Set(graph.split(/\r?\n/u).filter(Boolean))].sort();
        const manifest = JSON.parse(
            readFileSync(join(output, `${entry}-components.json`), 'utf8'),
        ) as KeyComponents | WasmComponents;
        const actual = manifest.modules.map((module) =>
            typeof module === 'string' ? module : module.module,
        );
        assert.deepEqual(actual.sort(), expected);
        const notices = readFileSync(join(output, `${entry}-licenses.txt`), 'utf8');
        const collected = browserGoLicenses(root, `./cmd/${entry}`);
        assert.deepEqual(collected.map(({ module }) => module).sort(), expected);
        for (const module of collected) {
            assert(notices.includes(module.module));
            const license =
                entry === 'browser-key'
                    ? (manifest as KeyComponents).moduleLicenses[module.module]
                    : required(
                          (manifest as WasmComponents).modules.find(
                              (item) => item.module === module.module,
                          ),
                      ).license;
            assert.equal(license, module.license);
            assert(module.files.length > 0);
            for (const file of module.files) {
                assert(file.text.trim().length > 0);
                assert.equal(hash(file.text), file.sha256);
                assert(notices.includes(file.text), `${module.module}: missing ${file.path}`);
            }
        }
    });
}

test('documentation favicon checkout preserves source bytes on CRLF-default build hosts', () => {
    const root = fileURLToPath(new URL('../../', import.meta.url));
    const file = 'HEAD:docs/assets/favicon.svg';
    const canonical = execFileSync('git', ['cat-file', 'blob', file], { cwd: root });
    const windowsCheckout = execFileSync(
        'git',
        ['-c', 'core.autocrlf=true', 'cat-file', '--filters', file],
        { cwd: root },
    );
    assert(!canonical.includes(Buffer.from('\r\n')));
    assert.deepEqual(
        windowsCheckout,
        canonical,
        'the same raw browser input must be verified on Linux and Windows',
    );
});

test('release inventory binds actual built assets, Go/project inputs and separate npm license provenance', () => {
    const raw = readFileSync(join(output, 'browser-build.json'));
    const manifest = JSON.parse(raw.toString('utf8')) as BrowserManifest;
    for (const asset of manifest.assets) {
        const bytes = readFileSync(join(output, asset.name));
        assert.equal(bytes.length, asset.bytes);
        assert.equal(hash(bytes), asset.sha256);
    }
    assert(manifest.inputs.some((input) => input.name === 'pkg/recording/cast/verifier.go'));
    assert(manifest.inputs.some((input) => input.name === 'web/bun.lock'));
    const favicon = manifest.assets.find((asset) =>
        /^assets\/favicon-[A-Za-z0-9_-]+\.svg$/u.test(asset.name),
    );
    assert(favicon, 'the documentation favicon must be a bundled local asset');
    const faviconSource = readFileSync(new URL('../../docs/assets/favicon.svg', import.meta.url));
    assert.deepEqual(readFileSync(join(output, favicon.name)), faviconSource);
    assert(
        manifest.inputs.some(
            (input) =>
                input.name === 'docs/assets/favicon.svg' && input.sha256 === hash(faviconSource),
        ),
    );
    assert.equal(
        manifest.components.filter((component) => component.ecosystem === 'go-runtime').length,
        1,
    );
    assert.equal(
        manifest.components.some((component) => component.name === 'react-remove-scroll-bar'),
        false,
    );
    for (const name of ['@mui/material', '@mui/icons-material', '@emotion/react']) {
        const component = manifest.components.find((entry) => entry.name === name);
        assert(component);
        assert.equal(component.license, 'MIT');
        assert.equal(component.licenseTextSource, 'npm archive');
        assert.match(component.integrity, /^sha512-/u);
    }
    assert.equal(
        manifest.components.filter((component) => component.name === 'react-is').length,
        2,
        'root and nested production versions have separate notices',
    );
    assert(manifest.scope.includes('not-source-attestation'));
    writeBrowserRelease(pathToFileURL(`${output}/`));
    assert.equal(
        readFileSync(join(output, 'browser-build.json'), 'utf8'),
        raw.toString('utf8'),
        'same inputs produce byte-identical metadata',
    );
});

for (const mode of [
    'missing worker',
    'missing favicon',
    'changed wasm',
    'changed runtime',
    'conflicting Go module license',
    'linked asset',
    'unknown schema',
    'changed input snapshot',
]) {
    test(`release generation refuses ${mode} without publishing a new manifest`, () => {
        const temporary = mkdtempSync(
            join(process.env.TMPDIR || tmpdir(), 'bifroest-browser-inventory-'),
        );
        try {
            cpSync(output, temporary, { recursive: true });
            const before = readFileSync(join(temporary, 'browser-build.json'));
            if (mode === 'missing worker') {
                unlinkSync(join(temporary, 'browser-key-worker.js'));
            }
            if (mode === 'missing favicon') {
                const manifest = JSON.parse(before.toString('utf8')) as BrowserManifest;
                const favicon = manifest.assets.find((asset) =>
                    /^assets\/favicon-[A-Za-z0-9_-]+\.svg$/u.test(asset.name),
                );
                assert(favicon);
                unlinkSync(join(temporary, favicon.name));
            }
            if (mode === 'changed wasm') {
                writeFileSync(join(temporary, 'browser-key.wasm'), 'tampered');
            }
            if (mode === 'changed runtime') {
                writeFileSync(join(temporary, 'go-wasm-exec.js'), 'tampered');
            }
            if (mode === 'conflicting Go module license') {
                const metadata = JSON.parse(
                    readFileSync(join(temporary, 'browser-key-components.json'), 'utf8'),
                ) as KeyComponents;
                const transfer = JSON.parse(
                    readFileSync(join(temporary, 'browser-transfer-components.json'), 'utf8'),
                ) as WasmComponents;
                const shared = metadata.modules.find((name) =>
                    transfer.modules.some((module) => module.module === name),
                );
                assert(shared, 'the fixture needs a Go module shared by both artifacts');
                metadata.moduleLicenses[shared] = 'LicenseRef-conflict';
                writeFileSync(
                    join(temporary, 'browser-key-components.json'),
                    JSON.stringify(metadata),
                );
            }
            if (mode === 'linked asset') {
                symlinkSync(join(output, 'browser-key.wasm'), join(temporary, 'link.wasm'));
            }
            if (mode === 'unknown schema') {
                const metadata = JSON.parse(
                    readFileSync(join(temporary, 'frontend-components.json'), 'utf8'),
                );
                metadata.schema = 'unknown';
                writeFileSync(
                    join(temporary, 'frontend-components.json'),
                    JSON.stringify(metadata),
                );
            }
            const snapshot =
                mode === 'changed input snapshot'
                    ? { ...captureBrowserInputs(), revision: 'b'.repeat(40) }
                    : undefined;
            assert.throws(() =>
                writeBrowserRelease(pathToFileURL(`${temporary}/`), undefined, snapshot),
            );
            assert.deepEqual(readFileSync(join(temporary, 'browser-build.json')), before);
        } finally {
            rmSync(temporary, { recursive: true, force: true });
        }
    });
}
