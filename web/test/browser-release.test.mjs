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
import { captureBrowserInputs, writeBrowserRelease } from '../scripts/browser-release.mjs';
import { completeReviewedInventory } from '../scripts/reviewed-go-modules.mjs';

const output = fileURLToPath(new URL('../../pkg/webui/assets/', import.meta.url));
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

test('initial JavaScript graph fits the existing four-worker admission budget without eager xterm or grid loading', () => {
    const html = readFileSync(join(output, 'index.html'), 'utf8');
    const entry = /src="\/_bifroest\/files\/(assets\/[A-Za-z0-9_-]+\.js)"/u.exec(html)?.[1];
    assert(entry, 'built document must name its same-origin module entry');
    const visited = new Set();
    function visit(file) {
        if (visited.has(file)) {
            return;
        }
        visited.add(file);
        const text = readFileSync(join(output, file), 'utf8');
        for (const match of text.matchAll(
            /(?:from|import)\s*["'](\.\/[A-Za-z0-9_.-]+\.js)["']/gu,
        )) {
            visit(join(dirname(file), match[1]));
        }
    }
    visit(entry);
    assert(visited.size <= 4, `initial module graph must stay bounded: ${[...visited].join(', ')}`);
    assert(
        [...visited].every(
            (file) => !/(?:xterm|AdminDataGrid|ArtifactPanel|ManagementPanel)-/u.test(file),
        ),
        'heavy views remain explicit lazy imports',
    );
});

test('reviewed Go module alternatives still require one exact version per complete module path', () => {
    const old = 'github.com/fxamacker/cbor/v2@v2.9.6';
    const current = 'github.com/fxamacker/cbor/v2@v2.10.0';
    const dependency = 'github.com/x448/float16@v0.8.4';
    const reviewed = [old, current, dependency];
    assert(completeReviewedInventory([old, dependency], reviewed));
    assert(completeReviewedInventory([current, dependency], reviewed));
    for (const actual of [
        [old],
        [dependency],
        [old, current],
        [old, current, dependency],
        [current, dependency, 'example.org/unreviewed@v1.0.0'],
        ['github.com/fxamacker/cbor/v2@v2.10.1', dependency],
        ['github.com/fxamacker/cbor/v2', dependency],
    ]) {
        assert.equal(completeReviewedInventory(actual, reviewed), false);
    }
});

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
    const manifest = JSON.parse(raw);
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
    'changed UUID license',
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
                const manifest = JSON.parse(before);
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
            if (mode === 'changed UUID license') {
                const metadata = JSON.parse(
                    readFileSync(join(temporary, 'browser-key-components.json')),
                );
                metadata.moduleLicenses['github.com/mr-tron/base58@v1.3.0'] = 'BSD-3-Clause';
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
                    readFileSync(join(temporary, 'frontend-components.json')),
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
